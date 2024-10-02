//! Circuit for proving the correctness of the Merkle tree commitment.

extern crate alloc;
use crate::commitment::commitment_scheme::CommitmentScheme;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Fixed, Instance, ProvingKey, Selector,
    },
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::SingleStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use poseidon::poseidon_hash::{ConstantLength, Hash, OrchardNullifier, Spec};
use rand_core::OsRng;

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
pub struct MerkleTreeCircuit<
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

#[derive(Clone)]
/// Witness for the Merkle tree
pub struct MerkleWitness {
    /// The leaf node
    pub leaf: u64,
    /// The elements in the path
    pub elements: Vec<u64>,
    /// The indices of the path
    pub indices: Vec<u64>,
}

impl MerkleWitness {
    /// Create a new Merkle witness
    pub fn new<T: AsRef<[u64]>>(leaf: u64, elements: T, indices: T) -> Self {
        Self {
            leaf,
            elements: elements.as_ref().to_vec(),
            indices: indices.as_ref().to_vec(),
        }
    }

    /// Convert to circuit-compatible format
    pub fn to_circuit_format<F: PrimeField>(&self) -> (F, Vec<F>, Vec<F>) {
        (
            F::from(self.leaf),
            self.elements.iter().map(|&x| F::from(x)).collect(),
            self.indices.iter().map(|&x| F::from(x)).collect(),
        )
    }
}

/// Prover for the Merkle tree
pub struct MerkleTreeProver {
    params: ParamsIPA<EqAffine>,
    pk: ProvingKey<EqAffine>,
    witness: MerkleWitness,
    circuit: MerkleTreeCircuit<OrchardNullifier, Fp, 3, 2>,
}

impl MerkleTreeProver {
    /// Initialize the parameters for the prover
    pub fn new(k: u32, witness: MerkleWitness) -> Self {
        let params = ParamsIPA::<EqAffine>::new(k);
        let (leaf, elements, indices) = witness.to_circuit_format::<Fp>();
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2> {
            leaf,
            elements,
            indices,
            _marker: PhantomData,
        };
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk, &circuit).expect("Cannot initialize proving key");
        Self {
            params,
            pk,
            witness,
            circuit,
        }
    }

    /// Create proof for the Merkle tree circuit
    pub fn create_proof(&self) -> Vec<u8> {
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);

        let public_inputs = [
            self.circuit.leaf,
            merkle_tree_commit_fp(
                &self.witness.leaf,
                &self.witness.elements,
                &self.witness.indices,
            ),
        ];

        create_proof::<
            IPACommitmentScheme<EqAffine>,
            ProverIPA<'_, EqAffine>,
            Challenge255<EqAffine>,
            OsRng,
            Blake2bWrite<Vec<u8>, EqAffine, Challenge255<EqAffine>>,
            MerkleTreeCircuit<OrchardNullifier, Fp, 3, 2>,
        >(
            &self.params,
            &self.pk,
            &[self.circuit.clone()],
            &[&[&public_inputs[..]]],
            OsRng,
            &mut transcript,
        )
        .expect("Failed to create proof");

        transcript.finalize()
    }

    /// Verify the proof
    pub fn verify(&self, proof: Vec<u8>, public_inputs: Vec<Fp>) -> bool {
        let strategy = SingleStrategy::new(&self.params);
        let mut transcript =
            Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(&proof[..]);

        verify_proof::<
            IPACommitmentScheme<EqAffine>,
            VerifierIPA<'_, EqAffine>,
            Challenge255<EqAffine>,
            Blake2bRead<&[u8], EqAffine, Challenge255<EqAffine>>,
            SingleStrategy<'_, EqAffine>,
        >(
            &self.params,
            self.pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok()
    }
}

/// Compute the root of a merkle tree given the path and the sibling nodes
pub fn merkle_tree_commit_fp(leaf: &u64, elements: &[u64], indices: &[u64]) -> Fp {
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

impl<S: Spec<Fp, W, R> + Clone, const W: usize, const R: usize> CommitmentScheme<Fp>
    for MerkleTreeCircuit<S, Fp, W, R>
{
    type Commitment = Fp;
    type Opening = Vec<u64>;
    type Witness = MerkleWitness;
    type PublicParams = ();

    fn setup(_k: Option<u32>) -> Self {
        Self {
            leaf: Fp::ZERO,
            elements: vec![Fp::ZERO],
            indices: vec![Fp::ZERO],
            _marker: PhantomData,
        }
    }

    fn commit(&self, witness: Self::Witness) -> Self::Commitment {
        merkle_tree_commit_fp(&witness.leaf, &witness.elements, &witness.indices)
    }

    fn open(&self, witness: Self::Witness) -> Self::Opening {
        witness.elements
    }

    fn verify(
        &self,
        commitment: Self::Commitment,
        opening: Self::Opening,
        witness: Self::Witness,
    ) -> bool {
        opening == witness.elements
            && commitment == merkle_tree_commit_fp(&witness.leaf, &opening, &witness.indices)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::MerkleTreeCircuit;
    use crate::commitment::commitment_scheme::CommitmentScheme;
    use crate::commitment::merkle_tree::{merkle_tree_commit_fp, MerkleTreeProver, MerkleWitness};
    use alloc::vec;
    use core::marker::PhantomData;
    use halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};
    use poseidon::poseidon_hash::*;
    use rand::{thread_rng, Rng};
    use rand_core::RngCore;

    #[test]
    fn test_correct_merkle_proof() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = merkle_tree_commit_fp(&leaf, &elements, &indices);
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
        let root = merkle_tree_commit_fp(&leaf, &elements, &indices);
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
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let witness = MerkleWitness::new(leaf, elements, indices);
        let prover = MerkleTreeProver::new(k, witness.clone());
        let proof = prover.create_proof();
        let root = prover.circuit.commit(witness.clone());
        let public_inputs = vec![Fp::from(leaf), root];
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
        let root = merkle_tree_commit_fp(&leaf, &elements, &indices);
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
        let leaf = 0u64;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let witness = MerkleWitness::new(leaf, elements, indices);

        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, 3, 2>::setup(None);
        let commitment = circuit.commit(witness.clone());
        let opening = circuit.open(witness.clone());
        let is_valid = circuit.verify(commitment, opening, witness);

        assert!(is_valid, "Verification should succeed for valid opening");
    }
}
