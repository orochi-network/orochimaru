// this is based on the implementation of https://github.com/DrPeterVanNostrand/halo2-merkle
extern crate alloc;
use alloc::{fmt, format, string::String, vec, vec::Vec};
use core::{fmt::Debug, iter, marker::PhantomData};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
        Selector,
    },
    poly::Rotation,
};
extern crate std;

#[derive(Clone, Debug)]
/// Poseidon config
pub struct PoseidonConfig<F: Field + PrimeField, const W: usize, const R: usize> {
    state: [Column<Advice>; W],
    sbox: Column<Advice>,
    rc_a: [Column<Fixed>; W],
    rc_b: [Column<Fixed>; W],
    s_full: Selector,
    s_partial: Selector,
    s_pad_and_add: Selector,
    half_full_rounds: usize,
    half_partial_rounds: usize,
    alpha: [u64; 4],
    round_constants: Vec<[F; W]>,
    m_reg: [[F; W]; W],
}
impl<F: Field + PrimeField, const W: usize, const R: usize> PoseidonConfig<F, W, R> {
    ///
    pub fn configure<S: Spec<F, W, R>>(meta: &mut ConstraintSystem<F>) -> Self {
        let (round_constants, m_reg, m_inv) = S::constants();
        assert_eq!(R, W - 1);
        let state = [0; W].map(|_| meta.advice_column());
        let sbox = meta.advice_column();
        let rc_a = [0; W].map(|_| meta.fixed_column());
        let rc_b = [0; W].map(|_| meta.fixed_column());
        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();
        let half_full_rounds = S::full_rounds() / 2;
        let half_partial_rounds = S::partial_rounds() / 2;
        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..W)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..W)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx], Rotation::cur());
                                pow_5(state_cur + rc_a) * m_reg[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("W > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid_0 = meta.query_advice(sbox, Rotation::cur());

            let rc_a0 = meta.query_fixed(rc_a[0], Rotation::cur());
            let rc_b0 = meta.query_fixed(rc_b[0], Rotation::cur());

            let s_partial = meta.query_selector(s_partial);

            use halo2_proofs::plonk::VirtualCells;
            let mid = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                let mid = mid_0.clone() * m_reg[idx][0];
                (1..W).fold(mid, |acc, cur_idx| {
                    let cur = meta.query_advice(state[cur_idx], Rotation::cur());
                    let rc_a = meta.query_fixed(rc_a[cur_idx], Rotation::cur());
                    acc + (cur + rc_a) * m_reg[idx][cur_idx]
                })
            };

            let next = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                (0..W)
                    .map(|next_idx| {
                        let next = meta.query_advice(state[next_idx], Rotation::next());
                        next * m_inv[idx][next_idx]
                    })
                    .reduce(|acc, next| acc + next)
                    .expect("W > 0")
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                let rc_b = meta.query_fixed(rc_b[idx], Rotation::cur());
                mid(idx, meta) + rc_b - next(idx, meta)
            };

            Constraints::with_selector(
                s_partial,
                std::iter::empty()
                    // state[0] round a
                    .chain(Some(pow_5(cur_0 + rc_a0) - mid_0.clone()))
                    // state[0] round b
                    .chain(Some(pow_5(mid(0, meta) + rc_b0) - next(0, meta)))
                    .chain((1..W).map(|idx| partial_round_linear(idx, meta)))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[R], Rotation::prev());
            let output_state_rate = meta.query_advice(state[R], Rotation::next());

            let s_pad_and_add = meta.query_selector(s_pad_and_add);

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
            sbox,
            rc_a,
            rc_b,
            s_full,
            s_partial,
            s_pad_and_add,
            half_full_rounds,
            half_partial_rounds,
            alpha,
            round_constants,
            m_reg,
        }
    }
}

/// Trait for a variable in the circuit.
pub trait Var<F: Field>: Clone + Debug + From<AssignedCell<F, F>> {
    /// The cell at which this variable was allocated.
    fn cell(&self) -> Cell;

    /// The value allocated to this variable.
    fn value(&self) -> Value<F>;
}

impl<F: Field> Var<F> for AssignedCell<F, F> {
    fn cell(&self) -> Cell {
        self.cell()
    }

    fn value(&self) -> Value<F> {
        self.value().cloned()
    }
}

/// A word in the Poseidon state.
#[derive(Clone, Debug)]
pub struct StateWord<F: Field>(AssignedCell<F, F>);

impl<F: Field> From<StateWord<F>> for AssignedCell<F, F> {
    fn from(state_word: StateWord<F>) -> AssignedCell<F, F> {
        state_word.0
    }
}

impl<F: Field> From<AssignedCell<F, F>> for StateWord<F> {
    fn from(cell_value: AssignedCell<F, F>) -> StateWord<F> {
        StateWord(cell_value)
    }
}

impl<F: Field> Var<F> for StateWord<F> {
    fn cell(&self) -> Cell {
        self.0.cell()
    }

    fn value(&self) -> Value<F> {
        self.0.value().cloned()
    }
}

pub trait Spec<F: Field + PrimeField, const T: usize, const R: usize>: fmt::Debug {
    /// The number of full rounds for this specification.
    ///
    /// This must be an even number.
    fn full_rounds() -> usize;

    /// The number of partial rounds for this specification.
    fn partial_rounds() -> usize;

    /// The S-box for this specification.
    fn sbox(val: F) -> F;

    /// Side-loaded index of the first correct and secure MDS that will be generated by
    /// the reference implementation.
    ///
    /// This is used by the default implementation of [`Spec::constants`]. If you are
    /// hard-coding the constants, you may leave this unimplemented.
    fn secure_mds() -> usize;

    /// Generates `(round_constants, mds, mds^-1)` corresponding to this specification.
    fn constants() -> (Vec<[F; T]>, [[F; T]; T], [[F; T]; T]);
}

#[derive(Debug)]
struct PoseidonState<F: Field, const W: usize>([StateWord<F>; W]);

impl<F: Field + PrimeField, const W: usize> PoseidonState<F, W> {
    fn full_round<const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_full, |_| {
            let q = self.0.iter().enumerate().map(|(idx, word)| {
                word.0
                    .value()
                    .map(|v| *v + config.round_constants[round][idx])
            });
            let r: Value<Vec<F>> = q.map(|q| q.map(|q| q.pow(&config.alpha))).collect();
            let m = &config.m_reg;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(F::ZERO, |acc, (j, r_j)| acc + m_i[j] * r_j)
                })
            });

            Ok((round + 1, state.collect::<Vec<_>>().try_into().unwrap()))
        })
    }

    fn partial_round<const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_partial, |region| {
            let m = &config.m_reg;
            let p: Value<Vec<_>> = self.0.iter().map(|word| word.0.value().cloned()).collect();

            let r: Value<Vec<_>> = p.map(|p| {
                let r_0 = (p[0] + config.round_constants[round][0]).pow(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + config.round_constants[round][i + 1]);
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            region.assign_advice(
                || format!("round_{} partial_sbox", round),
                config.sbox,
                offset,
                || r.as_ref().map(|r| r[0]),
            )?;

            let p_mid: Value<Vec<_>> = m
                .iter()
                .map(|m_i| {
                    r.as_ref().map(|r| {
                        m_i.iter()
                            .zip(r.iter())
                            .fold(F::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * r_j)
                    })
                })
                .collect();

            // Load the second round constants.
            let mut load_round_constant = |i: usize| {
                region.assign_fixed(
                    || format!("round_{} rc_{}", round + 1, i),
                    config.rc_b[i],
                    offset,
                    || Value::known(config.round_constants[round + 1][i]),
                )
            };
            for i in 0..W {
                load_round_constant(i)?;
            }

            let r_mid: Value<Vec<_>> = p_mid.map(|p| {
                let r_0 = (p[0] + config.round_constants[round + 1][0]).pow(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + config.round_constants[round + 1][i + 1]);
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            let state: Vec<Value<_>> = m
                .iter()
                .map(|m_i| {
                    r_mid.as_ref().map(|r| {
                        m_i.iter()
                            .zip(r.iter())
                            .fold(F::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * r_j)
                    })
                })
                .collect();

            Ok((round + 2, state.try_into().unwrap()))
        })
    }

    fn round<const R: usize>(
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<'_, F>) -> Result<(usize, [Value<F>; W]), Error>,
    ) -> Result<Self, Error> {
        // Enable the required gate.
        round_gate.enable(region, offset)?;

        // Load the round constants.
        let mut load_round_constant = |i: usize| {
            region.assign_fixed(
                || format!("round_{} rc_{}", round, i),
                config.rc_a[i],
                offset,
                || Value::known(config.round_constants[round][i]),
            )
        };
        for i in 0..W {
            load_round_constant(i)?;
        }

        // Compute the next round's state.
        let (next_round, next_state) = round_fn(region)?;

        let next_state_word = |i: usize| {
            let value = next_state[i];
            let var = region.assign_advice(
                || format!("round_{} state_{}", next_round, i),
                config.state[i],
                offset + 1,
                || value,
            )?;
            Ok(StateWord(var))
        };

        let next_state: Result<Vec<_>, _> = (0..W).map(next_state_word).collect();
        next_state.map(|next_state| PoseidonState(next_state.try_into().unwrap()))
    }
}

struct HashCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
    const L: usize,
> {
    message: Value<[F; L]>,
    // For the purpose of this test, witness the result.
    // TODO: Move this into an instance column.
    output: Value<F>,
    _marker: PhantomData<S>,
}

impl<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize, const L: usize>
    Circuit<F> for HashCircuit<S, F, W, R, L>
{
    type Config = PoseidonConfig<F, W, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            output: Value::unknown(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, W, R> {
        PoseidonConfig::configure::<S>(meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, W, R>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.state[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher =
            Hash::<_, _, S, ConstantLength<L>, W, R>::init(config, layouter.namespace(|| "init"))?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_var =
                    region.assign_advice(|| "load output", config.state[0], 0, || self.output)?;
                region.constrain_equal(output.cell(), expected_var.cell())
            },
        )
    }
}

pub trait Domain<F: Field + PrimeField, const RATE: usize> {
    /// Iterator that outputs padding field elements.
    type Padding: IntoIterator<Item = F>;

    /// The name of this domain, for debug formatting purposes.
    fn name() -> String;

    /// The initial capacity element, encoding this domain.
    fn initial_capacity_element() -> F;

    /// Returns the padding to be appended to the input.
    fn padding(input_len: usize) -> Self::Padding;
}

pub struct ConstantLength<const L: usize>;

impl<F: PrimeField, const RATE: usize, const L: usize> Domain<F, RATE> for ConstantLength<L> {
    type Padding = iter::Take<iter::Repeat<F>>;

    fn name() -> String {
        format!("ConstantLength<{}>", L)
    }

    fn initial_capacity_element() -> F {
        // Capacity value is $length \cdot 2^64 + (o-1)$ where o is the output length.
        // We hard-code an output length of 1.
        F::from_u128((L as u128) << 64)
    }

    fn padding(input_len: usize) -> Self::Padding {
        assert_eq!(input_len, L);
        // For constant-input-length hashing, we pad the input with zeroes to a multiple
        // of RATE. On its own this would not be sponge-compliant padding, but the
        // Poseidon authors encode the constant length into the capacity element, ensuring
        // that inputs of different lengths do not share the same permutation.
        let k = (L + RATE - 1) / RATE;
        iter::repeat(F::ZERO).take(k * RATE - L)
    }
}

#[derive(Clone, Copy, Debug)]
/// Merkle tree config
pub struct MerkleTreeConfig<F: Field + PrimeField> {
    // the root of the merkle tree
    root: Column<Instance>,
    // the path from the leaf to the root of the tree
    path: Column<Advice>,
    // the sibling nodes of each node in the path
    sibling: Column<Advice>,
    // the selectors
    selector: Column<Fixed>,
    selector_root: Selector,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> MerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let selector = meta.fixed_column();
        let root = meta.instance_column();
        let path = meta.advice_column();
        let sibling = meta.advice_column();
        let selector_root = meta.selector();
        meta.enable_equality(root);

        // checking if the final value is equal to the root of the tree
        meta.create_gate("public instance", |meta| {
            let path = meta.query_advice(path, Rotation::cur());
            let root = meta.query_instance(root, Rotation::cur());
            let selector_root = meta.query_selector(selector_root);
            vec![selector_root * (path - root)]
        });

        // poseidon constraints
        // TODO: Write Poseidon constraints

        MerkleTreeConfig {
            root,
            path,
            sibling,
            selector,
            selector_root,
            _marker: PhantomData,
        }
    }
}

#[derive(Default)]
/// circuit for verifying the correctness of the opening
pub struct MemoryTreeCircuit<F: Field + PrimeField> {
    path: Vec<F>,
    sibling: Vec<F>,
}
impl<F: Field + PrimeField> Circuit<F> for MemoryTreeCircuit<F> {
    type Config = MerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MerkleTreeConfig::<F>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let size = self.path.len() - 1;
        let root = layouter.assign_region(
            || "merkle tree commitment",
            |mut region| {
                for i in 0..size {
                    self.assign(config, &mut region, i)?;
                }

                config.selector_root.enable(&mut region, size)?;
                let root = region.assign_advice(
                    || format!("the {}-th node of the path", size),
                    config.path,
                    size,
                    || Value::known(self.path[size]),
                )?;

                Ok(root.cell())
            },
        )?;
        layouter.constrain_instance(root, config.root, 0)?;
        Ok(())
    }
}

impl<F: Field + PrimeField> MemoryTreeCircuit<F> {
    fn assign(
        &self,
        config: MerkleTreeConfig<F>,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "selector",
            config.selector,
            offset,
            || Value::known(F::ONE),
        )?;

        region.assign_advice(
            || format!("the {}-th node of the path", offset),
            config.path,
            offset,
            || Value::known(self.path[offset]),
        )?;

        region.assign_advice(
            || format!("the {}-th sibling node", offset),
            config.sibling,
            offset,
            || Value::known(self.sibling[offset]),
        )?;

        Ok(())
    }
}
