extern crate alloc;
use core::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Advice, Any, Column,
        ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
        VirtualCells,
    },
    poly::{
        Rotation,
    },
};

use super::gadgets::{PaddedWord, PoseidonState, StateWord};
use super::poseidon_hash::{Absorbing, Domain, Spec, Mtrx, Squeezing, State};

/// The poseidon config
#[derive(Clone, Debug)]
pub struct PoseidonConfig<F: PrimeField, const T: usize, const R: usize> {
    pub(crate) state: [Column<Advice>; T],
    pub(crate) partial_sbox: Column<Advice>,
    pub(crate) sel_full_round: Selector,
    pub(crate) sel_partial_round: Selector,
    pub(crate) sel_pad_and_add: Selector,
    pub(crate) half_full_rounds: usize,
    pub(crate) half_partial_rounds: usize,
    pub(crate) rc_a: [Column<Fixed>; T],
    pub(crate) rc_b: [Column<Fixed>; T],
    pub(crate) round_constants: Vec<[F; T]>,
    pub(crate) alpha: [u64; 4],
    pub(crate) m_reg: Mtrx<F, T>,
}

/// The poseidon config
#[derive(Debug, Clone)]
pub struct PoseidonChip<F: PrimeField, const T: usize, const R: usize> {
    /// The config
    pub config: PoseidonConfig<F, T, R>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField, const T: usize, const R: usize> PoseidonChip<F, T, R> {
    /// Constructor for the Poseidon chip
    pub fn new(config: PoseidonConfig<F, T, R>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// Configure the poseidon circuit
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

        let config = PoseidonConfig {
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
        };

        Self {
            config,
            _marker: PhantomData,
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
                        self.config.state[i],
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
                self.config.sel_pad_and_add.enable(&mut region, 1)?;

                // Load the initial state into this region.
                let load_state_word = |i: usize| {
                    initial_state[i]
                        .0
                        .copy_advice(
                            || format!("load state_{}", i),
                            &mut region,
                            self.config.state[i],
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
                                    self.config.rc_b[i],
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
                        self.config.state[i],
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
                        .assign_advice(|| format!("load output_{}", i), self.config.state[i], 2, || value)
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
                let state = PoseidonState::load::<D, R>(&mut region, &self, initial_state)?;

                let state = (0..self.config.half_full_rounds).try_fold(state, |state, r| {
                    state.full_round::<D, R>(&mut region, &self, r, r)
                })?;

                let state = (0..self.config.half_partial_rounds).try_fold(state, |state, r| {
                    state.partial_round::<D, R>(
                        &mut region,
                        &self,
                        self.config.half_full_rounds + 2 * r,
                        self.config.half_full_rounds + r,
                    )
                })?;

                let state = (0..self.config.half_full_rounds).try_fold(state, |state, r| {
                    state.full_round::<D, R>(
                        &mut region,
                        &self,
                        self.config.half_full_rounds + 2 * self.config.half_partial_rounds + r,
                        self.config.half_full_rounds + self.config.half_partial_rounds + r,
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