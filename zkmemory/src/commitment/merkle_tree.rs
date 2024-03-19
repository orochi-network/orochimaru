// this is based on the implementation of https://github.com/DrPeterVanNostrand/halo2-merkle
extern crate alloc;
use alloc::{format, vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
/// Poseidon config
pub struct PoseidonConfig<F: Field + PrimeField> {
    path: Column<Advice>,
    sibling: Column<Advice>,
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> PoseidonConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        path: Column<Advice>,
        sibling: Column<Advice>,
        selector: Column<Fixed>,
    ) -> Self {
        meta.create_gate("parent value equals to hash of children's values", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur_path = meta.query_advice(path, Rotation::cur());
            let prev_path = meta.query_advice(path, Rotation::prev());
            let prev_sibling = meta.query_advice(sibling, Rotation::prev());
            // TODO: insert the constraints for poseidon hash here
            vec![cur_path * prev_path * prev_sibling]
        });

        PoseidonConfig {
            path,
            sibling,
            _marker: PhantomData,
        }
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
    // the config for checking poseidon constraints
    poseidon_config: PoseidonConfig<F>,
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
        let poseidon_config = PoseidonConfig::<F>::configure(meta, path, sibling, selector);

        MerkleTreeConfig {
            root,
            path,
            sibling,
            poseidon_config,
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
