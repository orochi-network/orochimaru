//! The poseidon circuit, with most details based from
//! [Zcash implementation](https://github.com/summa-dev/halo2/blob/main/halo2_gadgets/src/poseidon/pow5.rs).
//! We originally wanted to import the implementation from Zcash's library directly.
//! However, since we are using the Halo2 version from PSE, we need to
//! clone many functions and fix some details so that the implementation
//! will be compatible with our implementation.
extern crate alloc;
use core::marker::PhantomData;

use alloc::string::ToString;
use alloc::{format, vec::Vec};
use ff::PrimeField;
use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Any, Constraints};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells,
    },
    poly::Rotation,
};

use super::gadgets::{Hash, PaddedWord, PoseidonState, StateWord};
use super::poseidon_hash::{Absorbing, ConstantLength, Domain, Mtrx, Spec, Squeezing, State};

/// The poseidon config
#[derive(Clone, Debug)]
pub struct PoseidonConfig<F: PrimeField, const T: usize, const R: usize> {
    pub(crate) state: [Column<Advice>; T],
    pub(crate) partial_sbox: Column<Advice>,
    pub(crate) sel_full_round: Selector,
    pub(crate) sel_partial_round: Selector,
    pub(crate) sel_pad_and_add: Selector,
    half_full_rounds: usize,
    half_partial_rounds: usize,
    pub(crate) rc_a: [Column<Fixed>; T],
    pub(crate) rc_b: [Column<Fixed>; T],
    pub(crate) round_constants: Vec<[F; T]>,
    pub(crate) alpha: [u64; 4],
    pub(crate) m_reg: Mtrx<F, T>,
}

impl<F: PrimeField, const T: usize, const R: usize> PoseidonConfig<F, T, R> {
    /// Create the gates of Poseidon
    pub fn configure<S: Spec<F, T, R>>(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; T],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; T],
        rc_b: [Column<Fixed>; T],
    ) -> Self {
        assert_eq!(R, T - 1);
        // Generate constants for the Poseidon permutation.
        // This gadget requires R_F and R_P to be even.
        assert!(S::full_rounds() & 1 == 0);
        assert!(S::partial_rounds() & 1 == 0);
        let half_full_rounds = S::full_rounds() / 2;
        let half_partial_rounds = S::partial_rounds() / 2;
        let (round_constants, m_reg, m_inv) = S::constants();

        // This allows state words to be initialized (by constraining them equal to fixed
        // values), and used in a permutation from an arbitrary region. rc_a is used in
        // every permutation round, while rc_b is empty in the initial and final full
        // rounds, so we use rc_b as "scratch space" for fixed values (enabling potential
        // layouter optimisations).
        for column in core::iter::empty()
            .chain(state.iter().cloned().map(Column::<Any>::from))
            .chain(rc_b.iter().cloned().map(Column::<Any>::from))
        {
            meta.enable_equality(column);
        }

        let sel_full_round = meta.selector();
        let sel_partial_round = meta.selector();
        let sel_pad_and_add = meta.selector();

        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(sel_full_round);

            Constraints::with_selector(
                s_full,
                (0..T)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..T)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx], Rotation::cur());
                                pow_5(state_cur + rc_a) * m_reg[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("T > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid_0 = meta.query_advice(partial_sbox, Rotation::cur());

            let rc_a0 = meta.query_fixed(rc_a[0], Rotation::cur());
            let rc_b0 = meta.query_fixed(rc_b[0], Rotation::cur());

            let s_partial = meta.query_selector(sel_partial_round);

            let mid = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                let mid = mid_0.clone() * m_reg[idx][0];
                (1..T).fold(mid, |acc, cur_idx| {
                    let cur = meta.query_advice(state[cur_idx], Rotation::cur());
                    let rc_a = meta.query_fixed(rc_a[cur_idx], Rotation::cur());
                    acc + (cur + rc_a) * m_reg[idx][cur_idx]
                })
            };

            let next = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                (0..T)
                    .map(|next_idx| {
                        let next = meta.query_advice(state[next_idx], Rotation::next());
                        next * m_inv[idx][next_idx]
                    })
                    .reduce(|acc, next| acc + next)
                    .expect("T > 0")
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                let rc_b = meta.query_fixed(rc_b[idx], Rotation::cur());
                mid(idx, meta) + rc_b - next(idx, meta)
            };

            Constraints::with_selector(
                s_partial,
                core::iter::empty()
                    // state[0] round a
                    .chain(Some(pow_5(cur_0 + rc_a0) - mid_0.clone()))
                    // state[0] round b
                    .chain(Some(pow_5(mid(0, meta) + rc_b0) - next(0, meta)))
                    .chain((1..T).map(|idx| partial_round_linear(idx, meta)))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[R], Rotation::prev());
            let output_state_rate = meta.query_advice(state[R], Rotation::next());

            let s_pad_and_add = meta.query_selector(sel_pad_and_add);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed columns and
                // then constraining the corresponding input columns to be equal to it.
                initial_state + input - output_state
            };

            Constraints::with_selector(
                s_pad_and_add,
                (0..R)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        PoseidonConfig {
            state,
            partial_sbox,
            sel_full_round,
            sel_partial_round,
            sel_pad_and_add,
            half_full_rounds,
            half_partial_rounds,
            rc_a,
            rc_b,
            round_constants,
            alpha,
            m_reg,
        }
    }

    /// Get the initial state
    pub fn initial_state<D: Domain<F, R>>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<State<StateWord<F>, T>, Error> {
        let state = layouter.assign_region(
            || "initial state for domain".to_string(),
            |mut region| {
                let mut state = Vec::with_capacity(T);
                let mut load_state_word = |i: usize, value: F| -> Result<_, Error> {
                    let var = region.assign_advice_from_constant(
                        || format!("state_{}", i),
                        self.state[i],
                        0,
                        value,
                    )?;
                    state.push(StateWord(var));

                    Ok(())
                };
                for i in 0..R {
                    load_state_word(i, F::ZERO)?;
                }
                load_state_word(R, D::initial_capacity_element())?;
                Ok(state)
            },
        )?;

        Ok(state.try_into().expect("unable to get state"))
    }

    /// Add the input
    pub fn add_input(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<StateWord<F>, T>,
        input: &Absorbing<PaddedWord<F>, R>,
    ) -> Result<State<StateWord<F>, T>, Error> {
        layouter.assign_region(
            || "add input for domain".to_string(),
            |mut region| {
                self.sel_pad_and_add.enable(&mut region, 1)?;

                // Load the initial state into this region.
                let load_state_word = |i: usize| {
                    initial_state[i]
                        .0
                        .copy_advice(
                            || format!("load state_{}", i),
                            &mut region,
                            self.state[i],
                            0,
                        )
                        .map(StateWord)
                };
                let initial_state: Result<Vec<_>, Error> = (0..T).map(load_state_word).collect();
                let initial_state = initial_state?;

                // Load the input into this region.
                let load_input_word = |i: usize| {
                    let (cell, value) = match input.0[i].clone() {
                        Some(PaddedWord::Message(word)) => (word.cell(), word.value().copied()),
                        Some(PaddedWord::Padding(padding_value)) => {
                            let cell = region
                                .assign_fixed(
                                    || format!("load pad_{}", i),
                                    self.rc_b[i],
                                    1,
                                    || Value::known(padding_value),
                                )?
                                .cell();
                            (cell, Value::known(padding_value))
                        }
                        _ => panic!("Input is not padded"),
                    };
                    let var = region.assign_advice(
                        || format!("load input_{}", i),
                        self.state[i],
                        1,
                        || value,
                    )?;
                    region.constrain_equal(cell, var.cell())?;

                    Ok(StateWord(var))
                };
                let input: Result<Vec<_>, Error> = (0..R).map(load_input_word).collect();
                let input = input?;

                // Constrain the output.
                let constrain_output_word = |i: usize| {
                    let value = initial_state[i].0.value().copied()
                        + input
                            .get(i)
                            .map(|word| word.0.value().cloned())
                            // The capacity element is never altered by the input.
                            .unwrap_or_else(|| Value::known(F::ZERO));
                    region
                        .assign_advice(|| format!("load output_{}", i), self.state[i], 2, || value)
                        .map(StateWord)
                };
                let output: Result<Vec<_>, Error> = (0..T).map(constrain_output_word).collect();
                output.map(|output| output.try_into().expect("cannot get output"))
            },
        )
    }

    /// Runs the Poseidon permutation on the given state. Given inputs a state,
    /// a MDS matrix and a list of round_constants, this function transform the
    /// state into a new state.
    pub fn permute<D: Domain<F, R>>(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<StateWord<F>, T>,
    ) -> Result<State<StateWord<F>, T>, Error> {
        layouter.assign_region(
            || "permute state",
            |mut region| {
                // Load the initial state into this region.
                let state = PoseidonState::load::<D, R>(&mut region, self, initial_state)?;

                let state = (0..self.half_full_rounds).try_fold(state, |state, r| {
                    state.full_round::<D, R>(&mut region, self, r, r)
                })?;

                let state = (0..self.half_partial_rounds).try_fold(state, |state, r| {
                    state.partial_round::<D, R>(
                        &mut region,
                        self,
                        self.half_full_rounds + 2 * r,
                        self.half_full_rounds + r,
                    )
                })?;

                let state = (0..self.half_full_rounds).try_fold(state, |state, r| {
                    state.full_round::<D, R>(
                        &mut region,
                        self,
                        self.half_full_rounds + 2 * self.half_partial_rounds + r,
                        self.half_full_rounds + self.half_partial_rounds + r,
                    )
                })?;

                Ok(state.0)
            },
        )
    }

    /// Get the output of the hash
    pub fn get_output(state: &State<StateWord<F>, T>) -> Squeezing<StateWord<F>, R> {
        Squeezing(
            state[..R]
                .iter()
                .map(|word| Some(word.clone()))
                .collect::<Vec<Option<StateWord<F>>>>()
                .try_into()
                .expect("cannot get state"),
        )
    }
}

#[derive(Debug)]
/// The poseidon circuit
pub struct PoseidonCircuit<
    S: Spec<F, T, R>,
    F: PrimeField,
    D: Domain<F, R>,
    const T: usize,
    const R: usize,
    const L: usize,
> {
    message: [F; L],
    // For the purpose of this test, witness the result.
    // TODO: Move this into an instance column.
    output: F,
    _marker: PhantomData<D>,
    _marker2: PhantomData<S>,
}
impl<
        S: Spec<F, T, R>,
        F: PrimeField,
        D: Domain<F, R> + Clone,
        const T: usize,
        const R: usize,
        const L: usize,
    > Circuit<F> for PoseidonCircuit<S, F, D, T, R, L>
{
    type Config = PoseidonConfig<F, T, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: [F::ZERO; L],
            output: F::ZERO,
            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, T, R> {
        let state = (0..T)
            .map(|_| meta.advice_column())
            .collect::<Vec<Column<Advice>>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..T)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        let rc_b = (0..T)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        meta.enable_constant(rc_b[0]);
        PoseidonConfig::configure::<S>(
            meta,
            state.try_into().expect("could not load state"),
            partial_sbox,
            rc_a.try_into().expect("could not load rc_a"),
            rc_b.try_into().expect("could not load rc_b"),
        )
    }
    fn synthesize(
        &self,
        config: PoseidonConfig<F, T, R>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = Value::known(self.message[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.state[i],
                        0,
                        || value,
                    )
                };
                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().expect("cannot unwrap message"))
            },
        )?;

        let hasher = Hash::<F, S, ConstantLength<L>, T, R>::init(
            config.clone(),
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_var = region.assign_advice(
                    || "load output",
                    config.state[0],
                    0,
                    || Value::known(self.output),
                )?;
                region.constrain_equal(output.cell(), expected_var.cell())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::PoseidonCircuit;
    use super::*;
    use crate::poseidon::poseidon_hash::{Hash, OrchardNullifier};
    use alloc::vec;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use rand::rngs::OsRng;
  
    #[test]
    fn poseidon_hash() {
        let rng = OsRng;

        let message = [Fp::random(rng), Fp::random(rng)];
        let output = Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let k = 6;
        let circuit = PoseidonCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2, 2> {
            message,
            output,
            _marker: PhantomData,
            _marker2: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).expect("cannot prove");
        assert_eq!(prover.verify(), Ok(()))
    }
}
