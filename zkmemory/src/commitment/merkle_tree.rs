// this is based on the implementation of https://github.com/DrPeterVanNostrand/halo2-merkle
extern crate alloc;
use alloc::{fmt, format, string::String, vec, vec::Vec};
use core::fmt::Debug;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
        Selector,
    },
    poly::Rotation,
};
use poseidon::poseidon_constraints::*;

use crate::poseidon::{self, poseidon::Spec};
extern crate std;

#[derive(Clone, Debug)]
/// Merkle tree config
pub struct MerkleTreeConfig<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize>
{
    poseidon_config: PoseidonConfig<F, W, R>,
    advice: [Column<Advice>; 3],
    // the selectors
    selector: Column<Fixed>,
    selector_root: Selector,
    _marker: PhantomData<S>,
}

impl<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize>
    MerkleTreeConfig<S, F, W, R>
{
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let selector = meta.fixed_column();
        let root = meta.instance_column();
        let path = meta.advice_column();
        let sibling = meta.advice_column();
        let selector_root = meta.selector();
        let advice = [0; 3].map(|_| meta.advice_column());
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
        let poseidon_config = Pow5Chip::<F, W, R>::configure::<S>(meta);

        MerkleTreeConfig {
            poseidon_config,
            advice,
            selector,
            selector_root,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Default)]
/// circuit for verifying the correctness of the opening
pub struct MemoryTreeCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
> {
    root: F,
    path: Vec<F>,
    sibling: Vec<F>,
    _marker: PhantomData<S>,
}
impl<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize> Circuit<F>
    for MemoryTreeCircuit<S, F, W, R>
{
    type Config = MerkleTreeConfig<S, F, W, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MerkleTreeConfig::<S, F, W, R>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let size = self.path.len() - 1;

        Ok(())
    }
}

impl<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize>
    MemoryTreeCircuit<S, F, W, R>
{
    fn assign(
        &self,
        config: MerkleTreeConfig<S, F, W, R>,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
}
