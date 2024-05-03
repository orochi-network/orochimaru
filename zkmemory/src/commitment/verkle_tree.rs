//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;

use crate::poseidon::poseidon_hash::{ConstantLength, Hash, Spec};
use alloc::{vec, vec::Vec};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
/// Verkle tree config
pub struct VerkleTreeConfig<F: Field + PrimeField> {
    advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    indices: Column<Advice>,
    selector: Column<Fixed>,
    selector_zero: Selector,
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> VerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> Self {
        let advice = [0; 2].map(|_| meta.advice_column());
        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
        let indices = meta.advice_column();
        for i in advice {
            meta.enable_equality(i);
        }

        let one = Expression::Constant(F::ONE);

        // for i=0 indices[i] is equal to zero or one
        // we handle i=0 seperately with selector_zero, since we are using
        // a common selector for the other gates.
        meta.create_gate("indices must be 0 or 1", |meta| {
            let selector_zero = meta.query_selector(selector_zero);
            let indices = meta.query_advice(indices, Rotation::cur());
            vec![selector_zero * indices.clone() * (one.clone() - indices)]
        });

        // for all i>=1 indices[i] is equal to zero or one
        meta.create_gate("indices must be 0 or 1", |meta| {
            let indices = meta.query_advice(indices, Rotation::cur());
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![selector * indices.clone() * (one.clone() - indices)]
        });

        VerkleTreeConfig {
            advice,
            instance,
            indices,
            selector,
            selector_zero,
            _marker: PhantomData,
        }
    }
}
///
#[derive(Default)]
pub(crate) struct VerkleTreeCircuit<F: Field + PrimeField> {
    pub(crate) leaf: F,
    pub(crate) non_leaf_elements: Vec<F>,
    pub(crate) indices: Vec<F>,
}

impl<F: Field + PrimeField> Circuit<F> for VerkleTreeCircuit<F> {
    type Config = VerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerkleTreeConfig::<F>::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        assert_eq!(self.indices.len(), self.non_leaf_elements.len());
        let mut v = vec![self.leaf];

        let leaf_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| {
                region.assign_advice(
                    || "assign leaf",
                    config.advice[0],
                    0,
                    || Value::known(self.leaf),
                )
            },
        )?;

        let root = layouter.assign_region(
            || "assign root",
            |mut region| {
                region.assign_advice(
                    || "assign root",
                    config.advice[0],
                    0,
                    || Value::known(v[self.indices.len()]),
                )
            },
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(root.cell(), config.instance, 1)?;
        Ok(())
    }
}
