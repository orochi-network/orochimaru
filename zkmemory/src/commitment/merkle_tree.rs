//! Circuit for proving the correctness of the Merkle tree commitment.

extern crate alloc;
use crate::poseidon::poseidon_hash::{ConstantLength, Hash, Spec};
use alloc::{vec, vec::Vec};
use core::fmt::Debug;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
/// Merkle tree config
pub struct MerkleTreeConfig<F: Field + PrimeField> {
    advice: [Column<Advice>; 3],
    indices: Column<Advice>,
    /// the instance of the config
    pub instance: Column<Instance>,
    selector: Column<Fixed>,
    selector_zero: Selector,
    _marker0: PhantomData<F>,
}

impl<F: Field + PrimeField> MerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> Self {
        let advice = [0; 3].map(|_| meta.advice_column());
        let indices = meta.advice_column();
        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
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

        // if indices[i]=0 then advice_cur[i][0]=advice_cur[i-1][2]
        // otherwise advice_cur[i][1]=advice_cur[i-1][2]
        meta.create_gate(
            "output of the current layer is equal to the left or right input of the next layer",
            |meta| {
                let advice_cur = advice.map(|x| meta.query_advice(x, Rotation::cur()));
                let advice_prev = advice.map(|x| meta.query_advice(x, Rotation::prev()));
                let indices = meta.query_advice(indices, Rotation::cur());
                let selector = meta.query_fixed(selector, Rotation::cur());
                vec![
                    selector
                        * ((one - indices.clone())
                            * (advice_cur[0].clone() - advice_prev[2].clone())
                            + indices * (advice_cur[1].clone() - advice_prev[2].clone())),
                ]
            },
        );

        MerkleTreeConfig {
            advice,
            indices,
            instance,
            selector,
            selector_zero,
            _marker0: PhantomData,
        }
    }
}

#[derive(Default)]
/// Merkle tree circuit
pub(crate) struct MemoryTreeCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
> {
    // the leaf node we would like to open
    pub(crate) leaf: F,
    // the values of the sibling nodes
    pub(crate) elements: Vec<F>,
    // the index of the path
    pub(crate) indices: Vec<F>,
    _marker: PhantomData<S>,
}
impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize> Circuit<F>
    for MemoryTreeCircuit<S, F, W, R>
{
    type Config = MerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: F::ZERO,
            elements: vec![F::ZERO],
            indices: vec![F::ZERO],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        MerkleTreeConfig::<F>::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        assert_eq!(self.indices.len(), self.elements.len());
        let mut v = vec![self.leaf];

        layouter.assign_region(
            || "Merkle proof",
            |mut region| {
                for i in 0..self.indices.len() {
                    let digest = self.assign(v[i], &mut region, config, i);
                    v.push(digest.expect("cannot get digest"));
                }
                Ok(())
            },
        )?;

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

        let digest = layouter.assign_region(
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
        layouter.constrain_instance(digest.cell(), config.instance, 1)?;
        Ok(())
    }
}

impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize>
    MemoryTreeCircuit<S, F, W, R>
{
    // Assign the elements in the path into the witness table
    fn assign(
        &self,
        digest: F,
        region: &mut Region<'_, F>,
        config: MerkleTreeConfig<F>,
        offset: usize,
    ) -> Result<F, Error> {
        if offset != 0 {
            region.assign_fixed(
                || "selector",
                config.selector,
                offset,
                || Value::known(F::ONE),
            )?;
            config.selector_zero.enable(region, offset)?;
        }
        let hash: F;
        region.assign_advice(
            || "indices",
            config.indices,
            offset,
            || Value::known(self.indices[offset]),
        )?;

        // assign the left input of the hash
        if self.indices[offset] == F::ZERO {
            region.assign_advice(
                || "left input",
                config.advice[0],
                offset,
                || Value::known(digest),
            )?;
            // assign the right input of the hash
            region.assign_advice(
                || "right input",
                config.advice[1],
                offset,
                || Value::known(self.elements[offset]),
            )?;
            // assign the output of the hash
            hash =
                Hash::<F, S, ConstantLength<2>, W, R>::init().hash([digest, self.elements[offset]]);

            region.assign_advice(|| "output", config.advice[2], offset, || Value::known(hash))?;
        } else {
            region.assign_advice(
                || "left input",
                config.advice[0],
                offset,
                || Value::known(self.elements[offset]),
            )?;
            region.assign_advice(
                || "right input",
                config.advice[1],
                offset,
                || Value::known(digest),
            )?;
            hash =
                Hash::<F, S, ConstantLength<2>, W, R>::init().hash([self.elements[offset], digest]);
            region.assign_advice(|| "output", config.advice[2], offset, || Value::known(hash))?;
        }
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::MemoryTreeCircuit;
    use crate::poseidon::poseidon_hash::*;
    use alloc::vec;
    use core::marker::PhantomData;
    use halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};
    use rand::{thread_rng, Rng};
    use rand_core::RngCore;

    /// Compute the root of a merkle tree given the path and the sibling nodes
    pub fn merkle_tree_commit(leaf: &u64, elements: &[u64], indices: &[u64]) -> Fp {
        let k = elements.len();
        let mut digest = Fp::from(*leaf);
        let mut message: [Fp; 2];
        for i in 0..k {
            if indices[i] == 0 {
                message = [digest, Fp::from(elements[i])];
            } else {
                message = [Fp::from(elements[i]), digest];
            }
            digest = Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
        }
        digest
    }

    #[test]
    fn test_correct_merkle_proof() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = merkle_tree_commit(&leaf, &elements, &indices);
        let leaf_fp = Fp::from(leaf);
        let indices = indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_correct_merkle_proof_part2() {
        let mut rng = thread_rng();
        let leaf = rng.next_u64();
        let k = 10;
        let indices = [
            rng.gen_range(0..2),
            rng.gen_range(0..2),
            rng.gen_range(0..2),
            rng.gen_range(0..2),
            rng.gen_range(0..2),
        ];
        let elements = [
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ];
        let root = merkle_tree_commit(&leaf, &elements, &indices);
        let leaf_fp = Fp::from(leaf);
        let indices = indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_wrong_merkle_proof() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = Fp::from(0);
        let leaf_fp = Fp::from(leaf);
        let indices = indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_wrong_merkle_part2() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = merkle_tree_commit(&leaf, &elements, &indices);
        let false_indices = [1u64, 0u64, 1u64, 1u64];
        let leaf_fp = Fp::from(leaf);
        let false_indices = false_indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices: false_indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_indices() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 2u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = Fp::from(0);
        let leaf_fp = Fp::from(leaf);
        let indices = indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_indices_part2() {
        let leaf = 0u64;
        let k = 10;
        let indices = [2u64, 1u64, 3u64, 4u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = Fp::from(0);
        let leaf_fp = Fp::from(leaf);
        let indices = indices.iter().map(|x| Fp::from(*x)).collect();
        let elements = elements.iter().map(|x| Fp::from(*x)).collect();
        let circuit = MemoryTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf: leaf_fp,
            indices,
            elements,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }
}
