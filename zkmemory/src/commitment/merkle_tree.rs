//! Circuit for proving the correctness of the Merkle tree commitment.

extern crate alloc;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::{bn256::{Bn256, G1Affine}, pasta::Fp},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector, ProvingKey,
        keygen_pk, keygen_vk, verify_proof, create_proof,
    },
    poly::{
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand_core::OsRng;
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

#[derive(Default, Debug, Clone)]
/// Merkle tree circuit
pub(crate) struct MerkleTreeCircuit<
    S: Spec<F, W, R> + Clone,
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

pub struct MerkleTreeProver<S, const W: usize, const R: usize>
where
    S: Spec<Fp, W, R> + Clone,
{
    params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
    circuit: MerkleTreeCircuit<S, Fp, W, R>,
}

impl<S, const W: usize, const R: usize> MerkleTreeProver<S, W, R>
where
    S: Spec<Fp, W, R> + Clone,
{
    /// Initialize the parameters for the prover
    pub fn new(k: u32, circuit: MerkleTreeCircuit<S, Fp, W, R>) -> Self {
        let params = ParamsKZG::<Bn256>::setup(k, OsRng); // TODO: add production level trusted setup
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk, &circuit).expect("Cannot initialize proving key");
        Self {
            params,
            pk,
            circuit,
        }
    }

    /// Create proof for the Merkle tree circuit
    pub fn create_proof(&self) -> Vec<u8> {
        let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
        
        let public_inputs = vec![self.circuit.leaf, self.circuit.commit()];
        
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            OsRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            MerkleTreeCircuit<S, F, W, R>,
        >(
            &self.params,
            &self.pk,
            &[self.circuit.clone()],
            &[&public_inputs],
            OsRng,
            &mut transcript,
        )
        .expect("Failed to create proof");

        transcript.finalize()
    }

    /// Verify the proof
    pub fn verify(&self, proof: Vec<u8>, public_inputs: Vec<F>) -> bool {
        let strategy = SingleStrategy::new(&self.params);
        let mut transcript = Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(&proof[..]);
        
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &self.params,
            self.pk.get_vk(),
            strategy,
            &[&public_inputs],
            &mut transcript,
        )
        .is_ok()
    }
}

pub fn merkle_tree_commit<F, S, const W: usize, const R: usize>(
    leaf: &F,
    elements: &[F],
    indices: &[bool],
) -> F
where
    F: PrimeField,
    S: Spec<F, W, R>,
{
    let mut digest = *leaf;
    for (&element, &index) in elements.iter().zip(indices.iter()) {
        let message = if !index {
            [digest, element]
        } else {
            [element, digest]
        };
        digest = Hash::<F, S, ConstantLength<2>, W, R>::init().hash(message);
    }
    digest
}

impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize> CommitmentScheme<F> for MerkleTreeCircuit<S, F, W, R> {
    type Commitment = F;
    type Opening = Vec<F>;
    type Witness = Vec<F>;
    type PublicParams = ();

    // TODO: add circuit
    fn setup(_k: Option<u32>) -> Self {
        Self {
            leaf: F::ZERO,
            elements: vec![F::ZERO],
            indices: vec![F::ZERO],
            _marker: PhantomData,
        }
    }

    fn commit(&self, witness: Self::Witness) -> Self::Commitment {
        let (leaf, elements) = witness.split_first().unwrap();
        let indices = elements.iter().map(|&x| x == F::ONE).collect::<Vec<_>>();
        merkle_tree_commit::<F, S, W, R>(leaf, elements, &indices)
    }

    fn open(&self, witness: Self::Witness) -> Self::Opening {
        witness[1..].to_vec()
    }

    fn verify(
        &self, 
        commitment: Self::Commitment,
        opening: Self::Opening,
        witness: Self::Witness,
    ) -> bool {
        let (leaf, elements) = witness.split_first().unwrap();
        let indices = elements.iter().map(|&x| x == F::ONE).collect::<Vec<_>>();
        opening == elements && commitment == merkle_tree_commit::<F, S, W, R>(leaf, &opening, &indices)
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
    use crate::commitment::commitment_scheme::CommitmentScheme;
    use crate::commitment::merkle_tree::MerkleTreeProver;

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
    fn test_merkle_proof_real_prover() {
        let k = 8; // Example circuit size parameter
        
        // Create a sample Merkle tree circuit
        let leaf = Fp::from(0u64);
        let elements = vec![Fp::from(3u64), Fp::from(4u64), Fp::from(5u64), Fp::from(6u64)];
        let indices = vec![Fp::from(0u64), Fp::from(0u64), Fp::from(1u64), Fp::from(1u64)];
        
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf,
            elements: elements.clone(),
            indices: indices.clone(),
            _marker: PhantomData,
        };

        // Create the prover
        let prover = MerkleTreeProver::new(k, circuit.clone());

        // Create the proof
        let proof = prover.create_proof();

        // Verify the proof
        let public_inputs = vec![leaf, circuit.commit()];
        let is_valid = prover.verify(proof, public_inputs);

        assert!(is_valid, "Merkle proof verification failed");
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

    /* #[test]
    fn test_correct_merkle_proof_commitment_scheme_trait() {
        let leaf = Fp::from(0u64);
        let elements = vec![Fp::from(3u64), Fp::from(4u64), Fp::from(5u64), Fp::from(6u64)];
        let indices = vec![Fp::from(0u64), Fp::from(0u64), Fp::from(1u64), Fp::from(1u64)];
        let witness = [vec![leaf], elements.clone(), indices].concat();

        // TODO change calling on their type to create instance and call  
        let pp = <MerkleTreeCircuit<OrchardNullifier, Fp, 3, 2> as CommitmentScheme<Fp>>::setup(None);
        let commitment = <MerkleTreeCircuit<OrchardNullifier, Fp, 3, 2> as CommitmentScheme<Fp>>::commit(witness.clone());
        let opening = <MerkleTreeCircuit<OrchardNullifier, Fp, 3, 2> as CommitmentScheme<Fp>>::open(witness.clone());
        let is_valid = <MerkleTreeCircuit<OrchardNullifier, Fp, 3, 2> as CommitmentScheme<Fp>>::verify(commitment, opening, witness);
        assert!(is_valid, "Verification should succeed for valid opening");
    }
 */
}
