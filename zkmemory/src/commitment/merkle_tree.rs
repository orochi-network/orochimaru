//! Circuit for proving the correctness of the Merkle tree commitment.

extern crate alloc;
use alloc::{vec, vec::Vec};
use alloc::boxed::Box;
use core::marker::PhantomData;
use core::error::Error as ErrorTrait;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use poseidon::poseidon_hash::{ConstantLength, Hash, Spec};
use crate::commitment::commitment_scheme::CommitmentScheme;

#[derive(Clone, Copy)]
/// Merkle tree config
pub struct MerkleTreeConfig<F: Field + PrimeField> {
    /// advice has 3 columns, the first column is the left input of the hash,
    /// the right column is the right input of the hash, and the last column
    /// is the output of the hash
    advice: [Column<Advice>; 3],
    indices: Column<Advice>,
    /// the instance of the config, consisting of the leaf we would like to
    /// open, and the merkle root.
    pub instance: Column<Instance>,
    /// the selectors
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
pub(crate) struct MerkleTreeCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
> {
    /// the leaf node we would like to open
    pub(crate) leaf: F,
    /// the values of the sibling nodes in the path
    pub(crate) elements: Vec<F>,
    /// the index of the path from the leaf to the merkle root
    pub(crate) indices: Vec<F>,
    _marker: PhantomData<S>,
}
impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize> Circuit<F>
    for MerkleTreeCircuit<S, F, W, R>
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
    MerkleTreeCircuit<S, F, W, R>
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

impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize> CommitmentScheme<F> for MerkleTreeCircuit<S, F, W, R> {
    type Value = F;
    type Commitment = F;
    type Opening = Vec<F>;
    type Witness = Vec<F>;
    type PublicParams = ();

    fn setup(_k: u32) -> Result<Self::PublicParams, Box<dyn ErrorTrait>> {
        Ok(())
    }

    fn commit(_pp: &Self::PublicParams, value: &Self::Value) -> Result<Self::Commitment, Box<dyn ErrorTrait>> {
        Ok(*value)
    }

    fn open(_pp: &Self::PublicParams, value: &Self::Value, witness: &Self::Witness) -> Result<Self::Opening, Box<dyn ErrorTrait>> {
        Ok(witness.clone())
    }

    fn verify(
        _pp: &Self::PublicParams,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        witness: &Self::Witness,
    ) -> Result<bool, Box<dyn ErrorTrait>> {
        Ok(opening == witness && *commitment == witness.last().copied().unwrap_or(F::ZERO))
    }

    fn create_proof(_pp: &Self::PublicParams, _circuit: Self) -> Result<Vec<u8>, Box<dyn ErrorTrait>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::MerkleTreeCircuit;
    use alloc::vec;
    use core::marker::PhantomData;
    use halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};
    use poseidon::poseidon_hash::*;
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
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
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
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
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
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
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
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
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
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
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
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
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
    fn test_correct_merkle_proof_commitment_scheme_trait() {
        let leaf = Fp::from(0u64);
        let elements = vec![Fp::from(3u64), Fp::from(4u64), Fp::from(5u64), Fp::from(6u64)];
        let indices = vec![Fp::from(0u64), Fp::from(0u64), Fp::from(1u64), Fp::from(1u64)];
        let root = merkle_tree_commit(&leaf, &elements, &indices);
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf,
            indices: indices.clone(),
            elements: elements.clone(),
            _marker: PhantomData,
        };

        let pp = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2>::setup(10).unwrap();
        let commitment = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2>::commit(&pp, &leaf).unwrap();
        let opening = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2>::open(&pp, &leaf, &indices).unwrap();
        let is_valid = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2>::verify(&pp, &commitment, &opening, &indices).unwrap();
        assert!(is_valid, "Verification should succeed for valid opening");

        let prover = MockProver::run(10, &circuit, vec![vec![leaf, root]]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

}
