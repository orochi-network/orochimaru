// this is based on the implementation of https://github.com/DrPeterVanNostrand/halo2-merkle
extern crate alloc;
use alloc::{format, vec, vec::Vec};
use core::{fmt::Debug, marker::PhantomData};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
        Selector,
    },
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
/// Poseidon config
pub struct PoseidonConfig<F: Field + PrimeField, const W: usize, const R: usize> {
    state: [Column<Advice>; W],
    sbox: Column<Advice>,
    rc_a: [Column<Fixed>; W],
    rc_b: [Column<Fixed>; W],
    s_full: Selector,
    s_partial: Selector,
    s_pad_and_add: Selector,
    alpha: [u64; 4],
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

        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..W)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx]);
                                pow_5(state_cur + rc_a) * m_reg[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
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
                    let rc_a = meta.query_fixed(rc_a[cur_idx]);
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
                    .expect("WIDTH > 0")
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<F>| {
                let rc_b = meta.query_fixed(rc_b[idx]);
                mid(idx, meta) + rc_b - next(idx, meta)
            };
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
            alpha,
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
    ) -> Result<(), Error> {
        Ok(())
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
