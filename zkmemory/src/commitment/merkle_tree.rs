//! Circuit for proving the correctness of the Merkle tree commitment.

extern crate alloc;
use alloc::format;
use alloc::{vec, vec::Vec};
use halo2_proofs::plonk::Instance;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Fixed, ProvingKey, Selector,
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
use poseidon::chip::{PoseidonChip, PoseidonConfig};
use poseidon::gadgets::Hash;
use poseidon::poseidon_hash::{
    ConstantLength, Domain, Hash as PoseidonHash, OrchardNullifier, Spec,
};

use rand_core::OsRng;

#[derive(Clone)]
/// Merkle tree config
pub struct MerkleTreeConfig<
    S: Spec<F, T, R> + Clone,
    F: Field + PrimeField,
    const T: usize,
    const R: usize,
> {
    /// the left input of the hash
    left_input: Column<Advice>,
    /// the right input of the hash
    right_input: Column<Advice>,
    /// output of the hash
    output: Column<Advice>,
    /// indices indicating whether the current node is a left or right child
    indices: Column<Advice>,
    /// the instance of the config, consisting of the leaf and the merkle root.
    pub instance: Column<Instance>,
    /// Selector for enabling the check `indices[i] = 0/1` (it will always enable)
    indices_selector: Selector,
    /// Selector for enabling the check that output of previous level is the
    /// left or right input of the current level (it will not enable at the first row)
    linking_selector: Selector,
    /// Selector for enabling the check that the leaf is equal to the first left or right input
    leaf_selector: Selector,
    /// the poseidon config
    pub poseidon_config: PoseidonConfig<F, T, R>,   

    _marker0: PhantomData<F>,
    _marker1: PhantomData<S>,
}

impl<S: Spec<F, T, R> + Clone, F: Field + PrimeField, const T: usize, const R: usize>
    MerkleTreeConfig<S, F, T, R>
{
    fn configure(meta: &mut ConstraintSystem<F>, instance: Column<Instance>) -> Self {
        let left_input = meta.advice_column();
        let right_input = meta.advice_column();
        let output = meta.advice_column();
        let indices = meta.advice_column();
        let indices_selector = meta.selector();
        let linking_selector = meta.selector();
        let leaf_selector = meta.selector();

        meta.enable_equality(left_input);
        meta.enable_equality(right_input);
        meta.enable_equality(output);

        let one = Expression::Constant(F::ONE);

        // for all i, indices[i] is equal to zero or one
        meta.create_gate("indices must be 0 or 1", |meta| {
            let indices = meta.query_advice(indices, Rotation::cur());
            // selector is always enabled
            let selector = meta.query_selector(indices_selector);
            // indices * (1 - indices) = 0
            vec![selector * indices.clone() * (one.clone() - indices)]
        });

        // for all i = 1..len-1, if indices[i] = 0, then left_input[i] = output[i-1]
        // else right_input[i] = output[i-1]
        meta.create_gate("linking between levels", |meta| {
            let left_input = meta.query_advice(left_input, Rotation::cur());
            let right_input = meta.query_advice(right_input, Rotation::cur());
            let output_prev = meta.query_advice(output, Rotation::prev());
            let indices = meta.query_advice(indices, Rotation::cur());
            let selector = meta.query_selector(linking_selector);
            // (1 - indices) * (left_input - output_prev) + indices * (right_input - output_prev) = 0
            vec![
                selector
                    * ((one.clone() - indices.clone()) * (left_input - output_prev.clone())
                        + indices * (right_input - output_prev)),
            ]
        });

        // the leaf is assigned to the first left or right input
        // we enforce the first instance (which contain the leaf) to be equal to the first left or right input
        // i.e. if indices[0] = 0, then left_input[0] = instance[0]
        // else right_input[0] = instance[0]
        // the `leaf_selector` = 1 only at the first row
        // (we cannot reuse `linking_selector` here although `leaf_selector` = !`linking_selector`
        // because halo2 does not allow (`1 - selector`), `selector` is must not be subtracted)
        meta.create_gate("linking leaf to instance", |meta| {
            let left_input = meta.query_advice(left_input, Rotation::cur());
            let right_input = meta.query_advice(right_input, Rotation::cur());
            let instance = meta.query_instance(instance, Rotation::cur());
            let indices = meta.query_advice(indices, Rotation::cur());
            let selector = meta.query_selector(leaf_selector);
            // selector * [(1 - indices) * (left_input - instance) + indices * (right_input - instance)] = 0
            vec![
                selector
                    * ((one.clone() - indices.clone()) * (left_input - instance.clone())
                        + indices * (right_input - instance)),
            ]
        });

        // configure the poseidon chip
        let state = (0..T)
            .map(|_| meta.advice_column())
            .collect::<Vec<Column<Advice>>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..T)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        let rc_b = (0..T)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        meta.enable_constant(rc_b[0]);

        let poseidon_chip = PoseidonChip::configure::<S>(
            meta,
            state.clone().try_into().expect("could not load state"),
            partial_sbox,
            rc_a.clone().try_into().expect("could not load rc_a"),
            rc_b.clone().try_into().expect("could not load rc_b"),
        );

        MerkleTreeConfig {
            left_input,
            right_input,
            output,
            instance,
            indices,
            indices_selector,
            linking_selector,
            leaf_selector,
            poseidon_config: poseidon_chip.config,
            _marker0: PhantomData,
            _marker1: PhantomData,
        }
    }
}

#[derive(Default, Debug, Clone)]
/// Merkle tree circuit
pub struct MerkleTreeCircuit<
    S: Spec<F, T, R> + Clone,
    F: Field + PrimeField,
    D: Domain<F, R> + Clone,
    const T: usize,
    const R: usize,
> {
    /// the values of the left nodes in the path
    pub(crate) lefts: Vec<F>,
    /// the values of the right nodes in the path
    pub(crate) rights: Vec<F>,
    /// the outputs of hash(left,right)
    pub(crate) outputs: Vec<F>,
    /// the indices of the path, 0 for left, 1 for right
    pub(crate) indices: Vec<F>,

    pub(crate) _marker0: PhantomData<S>,
    pub(crate) _marker1: PhantomData<D>,
}

impl<
        S: Spec<F, T, R> + Clone,
        F: Field + PrimeField,
        D: Domain<F, R> + Clone,
        const T: usize,
        const R: usize,
    > Circuit<F> for MerkleTreeCircuit<S, F, D, T, R>
{
    type Config = MerkleTreeConfig<S, F, T, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            lefts: vec![F::ZERO; self.lefts.len()],
            rights: vec![F::ZERO; self.rights.len()],
            outputs: vec![F::ZERO; self.outputs.len()],
            indices: vec![F::ZERO; self.indices.len()],
            _marker0: PhantomData,
            _marker1: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // instance column will contain the leaf and the merkle root
        // leaf = instance[0]
        // merkle_root = instance[1]
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        MerkleTreeConfig::<S, F, T, R>::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: MerkleTreeConfig<S, F, T, R>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // pre-check to ensure the lengths are consistent
        assert_eq!(self.indices.len(), self.lefts.len());
        assert_eq!(self.indices.len(), self.rights.len());
        assert_eq!(self.indices.len(), self.outputs.len());

        // create the poseidon chip, we will use it to create the sub-circuits of the Poseidon hash
        let chip: PoseidonChip<F, T, R> = PoseidonChip::new(config.poseidon_config.clone());

        // assign the lefts, rights, outputs values to the corresponding columns
        let (left_cells, right_cells, out_cells) = layouter.assign_region(
                || "Merkle Proof",
                |mut region| {
                    // enable the leaf selector at the first row
                    config.leaf_selector.enable(&mut region, 0)?;

                    let mut left_cells = vec![];
                    let mut right_cells = vec![];
                    let mut output_cells = vec![];
                    for i in 0..self.indices.len() {
                        // enable the indices selector at every row
                        config.indices_selector.enable(&mut region, i)?;
                        if i != 0 {
                            // enable the linking selector at every row except the first row
                            config.linking_selector.enable(&mut region, i)?;
                        }

                        // assign the left input of the hash at row i
                        let left = region.assign_advice(
                            || format!("left input {}", i),
                            config.left_input,
                            i,
                            || Value::known(self.lefts[i]),
                        )?;
                        left_cells.push(left);

                        // assign the right input of the hash at row i
                        let right = region.assign_advice(
                            || format!("right input {}", i),
                            config.right_input,
                            i,
                            || Value::known(self.rights[i]),
                        )?;
                        right_cells.push(right);

                        // assign the output of the hash at row i
                        let out = region.assign_advice(
                            || format!("output {}", i),
                            config.output,
                            i,
                            || Value::known(self.outputs[i]),
                        )?;
                        output_cells.push(out);

                        // assign the index (0 or 1) at row i
                        region.assign_advice(
                            || format!("indices {}", i),
                            config.indices,
                            i,
                            || Value::known(self.indices[i]),
                        )?;
                    }

                    // collect the cells we have assigned and return them
                    Ok((left_cells, right_cells, output_cells))
                },
            )?;

        // for each level in the path, we create a Poseidon hash sub-circuit
        // and then constrain that the output of the hash is equal to the output cell at that level
        for i in 0..self.indices.len() {
            // the input to the hash is [left_cells[i], right_cells[i]]
            let message = [left_cells[i].clone(), right_cells[i].clone()];
            
            // initialize the hasher
            let hasher = Hash::<F, S, ConstantLength<2>, T, R>::init(
                chip.clone(),
                layouter.namespace(|| "init"),
            )?;
            // compute the hash
            let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

            // create a dummy region to constraint that output = out_cells[i]
            layouter.assign_region(
                || "constrain output",
                |mut region| {
                    region.constrain_equal(output.cell(), out_cells[i].cell())
                },
            )?;

            // at the last level, we also constrain that the output is equal to the merkle root
            // which is stored in the second instance column
            if i == self.indices.len() - 1 {
                layouter.constrain_instance(output.cell(), config.instance, 1)?;
            }
        }

        Ok(())
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

    /// Convert to circuit-compatible format (using pasta Fp so OrchardNullifier fits the Spec impl)
    pub fn to_circuit_format(&self) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<Fp>) {
        assert_eq!(self.elements.len(), self.indices.len());
        let leaf = Fp::from(self.leaf);
        let mut lefts = vec![];
        let mut rights = vec![];
        let mut outputs = vec![];

        let mut current = leaf;
        for (i, &element) in self.elements.iter().enumerate() {
            let element_fp = Fp::from(element);
            if self.indices[i] == 0 {
                lefts.push(current);
                rights.push(element_fp);
            } else {
                lefts.push(element_fp);
                rights.push(current);
            }
            let output = PoseidonHash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash([lefts[i], rights[i]]);
            outputs.push(output);
            current = output;
        }
        (
            lefts,
            rights,
            outputs,
            self.indices.iter().map(|&x| Fp::from(x)).collect(),
        )
    }
}

/// Prover for the Merkle tree,
/// Specified the field is Fp
pub struct MerkleTreeProver<S, D, const T: usize, const R: usize>
where
    S: Spec<Fp, T, R> + Clone,
    D: Domain<Fp, R> + Clone,
{
    params: ParamsIPA<EqAffine>,
    pk: ProvingKey<EqAffine>,
    _marker0: PhantomData<S>,
    _marker1: PhantomData<D>,
}

impl<S, D, const T: usize, const R: usize> MerkleTreeProver<S, D, T, R>
where
    S: Spec<Fp, T, R> + Clone,
    D: Domain<Fp, R> + Clone,
{
    /// Initialize the parameters for the prover
    /// `k` is the log_2 of the size of the circuit
    /// `elements_len` is the length of the Merkle path
    pub fn new(k: u32, elements_len: usize) -> Self {
        // create a dummy circuit with zero values
        let dummy_circuit = MerkleTreeCircuit::<S, Fp, D, T, R> {
            lefts: vec![Fp::ZERO; elements_len],
            rights: vec![Fp::ZERO; elements_len],
            outputs: vec![Fp::ZERO; elements_len],
            indices: vec![Fp::ZERO; elements_len],
            _marker0: PhantomData,
            _marker1: PhantomData,
        };
        let params = ParamsIPA::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &dummy_circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk, &dummy_circuit).expect("Cannot initialize proving key");
        Self {
            params,
            pk,
            _marker0: PhantomData,
            _marker1: PhantomData,
        }
    }

    /// Create proof for the Merkle tree circuit given the real circuit
    pub fn create_proof(&self, real_circuit: MerkleTreeCircuit<S, Fp, D, T, R>) -> (Vec<u8>, Vec<Fp>) {
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);

        let leaf;
        if real_circuit.indices[0] == Fp::ZERO {
            leaf = real_circuit.lefts[0];
        } else {
            leaf = real_circuit.rights[0];
        }

        let public_inputs = [
            leaf,
            real_circuit.outputs[real_circuit.outputs.len() - 1],
        ];

        create_proof::<
            IPACommitmentScheme<EqAffine>,
            ProverIPA<'_, EqAffine>,
            Challenge255<EqAffine>,
            OsRng,
            Blake2bWrite<Vec<u8>, EqAffine, Challenge255<EqAffine>>,
            MerkleTreeCircuit<S, Fp, D, T, R>,
        >(
            &self.params,
            &self.pk,
            &[real_circuit.clone()],
            &[&[&public_inputs[..]]],
            OsRng,
            &mut transcript,
        )
        .expect("Failed to create proof");

        (transcript.finalize(), public_inputs.to_vec())
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
        digest =
            PoseidonHash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
    }
    digest
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::MerkleTreeCircuit;
    use crate::commitment::merkle_tree::{MerkleTreeProver, MerkleWitness};
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
        let witness = MerkleWitness::new(leaf, elements, indices);
        let (lefts, rights, outputs, indices) = witness.to_circuit_format();
        let public_inputs = vec![Fp::from(leaf), outputs[outputs.len() - 1]];
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            indices,
            lefts,
            rights,
            outputs,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()])
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
        
        let witness = MerkleWitness::new(leaf, elements, indices);
        let (lefts, rights, outputs, indices) = witness.to_circuit_format();
        let public_inputs = vec![Fp::from(leaf), outputs[outputs.len() - 1]];
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            lefts,
            rights,
            outputs,
            indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![public_inputs])
            .expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_wrong_merkle_proof_incorrect_instance() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        let root = Fp::from(0); // wrong root

        let witness = MerkleWitness::new(leaf, elements, indices);
        let (lefts, rights, outputs, indices) = witness.to_circuit_format();

        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            lefts,
            rights,
            outputs,
            indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), root]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_wrong_merkle_proof_incorrect_merkle_path() {
        let leaf = 0u64;
        let k = 10;
        
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        
        let witness = MerkleWitness::new(leaf, elements, indices);
        let (mut lefts, rights, outputs, indices) = witness.to_circuit_format();
        lefts[2] = Fp::from(0); // tamper the left input at the second level

        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            lefts,
            rights,
            outputs: outputs.clone(),
            indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), outputs[outputs.len() - 1]]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_wrong_merkle_proof_incorrect_indices() {
        let leaf = 0u64;
        let k = 10;
        
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        
        let witness = MerkleWitness::new(leaf, elements, indices);
        let (lefts, rights, outputs, mut indices) = witness.to_circuit_format();
        indices[2] = Fp::from(0); // tamper the index at the second level
        
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            lefts,
            rights,
            outputs: outputs.clone(),
            indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), outputs[outputs.len() - 1]]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }        
    
    #[test]
    fn test_wrong_merkle_proof_dummy_output() {
        let leaf = 0u64;
        let k = 10;
        
        let indices = [0u64, 0u64, 1u64, 1u64];
        let elements = [3u64, 4u64, 5u64, 6u64];
        
        let witness = MerkleWitness::new(leaf, elements, indices);
        let (lefts, rights, mut outputs, indices) = witness.to_circuit_format();
        
        // create dummy outputs 
        // related to issue 93
        outputs[0] = Fp::from(1);
        outputs[1] = Fp::from(2);
        outputs[2] = Fp::from(3);
        outputs[3] = Fp::from(4);

        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            lefts,
            rights,
            outputs: outputs.clone(),
            indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![vec![Fp::from(leaf), outputs[outputs.len() - 1]]])
            .expect("Cannot run the circuit");
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_merkle_proof_real_prover() {
        let leaf = 0u64;
        let k = 10;
        let indices = [0u64, 0u64, 0u64, 0u64];
        let elements = [3u64, 4u64, 5u64, 6u64];

        let witness = MerkleWitness::new(leaf, elements, indices);
        let (lefts, rights, outputs, indices) = witness.to_circuit_format();
        
        let circuit = MerkleTreeCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2> {
            lefts: lefts,
            rights: rights,
            outputs: outputs,
            indices: indices,
            _marker0: PhantomData,
            _marker1: PhantomData,
        };

        let prover = MerkleTreeProver::new(k, elements.len());
        
        let (proof, public_inputs) = prover.create_proof(circuit.clone());

        let is_valid = prover.verify(proof, public_inputs);
        
        assert!(is_valid, "Merkle proof verification failed");
    }

}
