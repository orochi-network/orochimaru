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
