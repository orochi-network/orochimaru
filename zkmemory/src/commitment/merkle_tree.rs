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

use crate::poseidon::{
    self,
    poseidon::{ConstantLength, Spec},
};
extern crate std;

#[derive(Clone, Debug)]
/// Merkle tree config
pub struct MerkleTreeConfig<F: Field + PrimeField, const W: usize, const R: usize> {
    poseidon_config: PoseidonConfig<F, W, R>,
    advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    // the selectors
    selector_swap: Selector,
}

impl<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize>
    MerkleTreeConfig<F, W, R>
{
    fn configure(
        meta: &mut ConstraintSystem<F>,
        hash_inputs: [Column<Advice>; W],
        instance: Column<Instance>,
    ) -> Self {
        let selector = meta.fixed_column();
        let root = meta.instance_column();
        let selector_root = meta.selector();
        let advice = [0; 3].map(|_| meta.advice_column());
        meta.enable_equality(root);
        let selector_swap = meta.selector();

        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);

        // Enforces that if the swap bit (c) is on, l=b and r=a. Otherwise, l=a and r=b.
        // s * (c * 2 * (b - a) - (l - a) - (b - r)) = 0
        // This applies only when the swap selector is enabled
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(selector_swap);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let l = meta.query_advice(col_a, Rotation::next());
            let r = meta.query_advice(col_b, Rotation::next());
            vec![
                s * (c * Expression::Constant(F::from(2)) * (b.clone() - a.clone())
                    - (l - a)
                    - (b - r)),
            ]
        });

        // poseidon constraints
        // TODO: Write Poseidon constraints
        let poseidon_config = Pow5Chip::<F, W, R>::configure::<S>(meta, hash_inputs);

        MerkleTreeConfig {
            poseidon_config,
            advice,
            instance,
            selector_swap,
        }
    }

    pub fn assing_leaf(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let node_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| region.assign_advice(|| "assign leaf", self.advice[0], 0, || leaf),
        )?;

        Ok(node_cell)
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        node_cell: &AssignedCell<F, F>,
        path_element: Value<F>,
        index: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (left, right) = layouter.assign_region(
            || "merkle prove layer",
            |mut region| {
                // Row 0

                node_cell.copy_advice(
                    || "copy node cell from previous prove layer",
                    &mut region,
                    self.advice[0],
                    0,
                )?;
                region.assign_advice(|| "assign element", self.advice[1], 0, || path_element)?;
                region.assign_advice(|| "assign index", self.advice[2], 0, || index)?;

                // Row 1
                let node_cell_value = node_cell.value().map(|x| *x);
                let (mut l, mut r) = (node_cell_value, path_element);
                index.map(|x| {
                    (l, r) = if x == F::ZERO { (l, r) } else { (r, l) };
                });

                // We need to perform the assignment of the row below in order to perform the swap check
                let left =
                    region.assign_advice(|| "assign left to be hashed", self.advice[0], 1, || l)?;
                let right = region.assign_advice(
                    || "assign right to be hashed",
                    self.advice[1],
                    1,
                    || r,
                )?;

                Ok((left, right))
            },
        )?;

        let digest = self.hash(layouter.namespace(|| "hash row constaint"), [left, right])?;
        Ok(digest)
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        input_cells: [AssignedCell<F, F>; 2],
    ) -> Result<AssignedCell<F, F>, Error> {
        let pow5_chip = Pow5Chip::construct(self.poseidon_config.clone());

        // initialize the hasher
        let hasher = Hash::<F, Pow5Chip<F, W, R>, S, ConstantLength<2>, W, R>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), input_cells)
    }
}

#[derive(Clone, Default)]
/// circuit for verifying the correctness of the opening
pub struct MemoryTreeCircuit<F: Field + PrimeField, const W: usize, const R: usize> {
    leaf: Value<F>,
    elements: Vec<Value<F>>,
    indices: Vec<Value<F>>,
}
impl<F: Field + PrimeField, const W: usize, const R: usize> Circuit<F>
    for MemoryTreeCircuit<F, W, R>
{
    type Config = MerkleTreeConfig<F, W, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let hash_inputs = [0; W].map(|_| meta.advice_column());
        let instance = meta.instance_column();
        MerkleTreeConfig::<F, W, R>::configure(meta, hash_inputs, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let leaf_cell = config.assing_leaf(layouter.namespace(|| "assign leaf"), self.leaf)?;
        let mut digest = config.merkle_prove_layer(
            layouter.namespace(|| "merkle_prove"),
            &leaf_cell,
            self.elements[0],
            self.indices[0],
        )?;

        for i in 1..self.elements.len() {
            digest = config.merkle_prove_layer(
                layouter.namespace(|| "next level"),
                &digest,
                self.elements[i],
                self.indices[i],
            )?;
        }

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0);
        layouter.constrain_instance(digest.cell(), config.instance, 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
