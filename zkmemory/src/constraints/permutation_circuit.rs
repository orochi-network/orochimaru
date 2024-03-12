use crate::{
    base::Base,
    machine::{MemoryInstruction, TraceRecord},
};
use core::marker::PhantomData;
use group::ff::{Field, FromUniformBytes, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, ProvingKey, Selector,
    },
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::CurveAffine;
use rand::Rng;
use rand_core::OsRng;
extern crate alloc;
use alloc::{vec, vec::Vec};

use super::common::CircuitExtension;

/// Define a chip struct that implements our instructions.
pub struct ShuffleChip<F: Field + PrimeField> {
    config: ShuffleConfig,
    _marker: PhantomData<F>,
}

/// Define that chip config struct
#[derive(Debug, Clone)]
pub struct ShuffleConfig {
    input_0: Column<Advice>,
    input_1: Column<Fixed>,
    shuffle_0: Column<Advice>,
    shuffle_1: Column<Advice>,
    s_input: Selector,
    s_shuffle: Selector,
}

impl<F: Field + PrimeField> ShuffleChip<F> {
    /// Construct a permutation chip using the config
    pub fn construct(config: ShuffleConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// configure the gates
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input_0: Column<Advice>,
        input_1: Column<Fixed>,
        shuffle_0: Column<Advice>,
        shuffle_1: Column<Advice>,
    ) -> ShuffleConfig {
        let s_shuffle = meta.complex_selector();
        let s_input = meta.complex_selector();
        meta.shuffle("shuffle", |meta| {
            let s_input = meta.query_selector(s_input);
            let s_shuffle = meta.query_selector(s_shuffle);
            let input_0 = meta.query_advice(input_0, Rotation::cur());
            let input_1 = meta.query_fixed(input_1, Rotation::cur());
            let shuffle_0 = meta.query_advice(shuffle_0, Rotation::cur());
            let shuffle_1 = meta.query_advice(shuffle_1, Rotation::cur());
            vec![
                (s_input.clone() * input_0, s_shuffle.clone() * shuffle_0),
                (s_input * input_1, s_shuffle * shuffle_1),
            ]
        });

        ShuffleConfig {
            input_0,
            input_1,
            shuffle_0,
            shuffle_1,
            s_input,
            s_shuffle,
        }
    }
}

/// Define the permutatioin circuit for the project
#[derive(Default, Clone, Debug)]
pub struct PermutationCircuit<F: Field + PrimeField> {
    // input_idx: an array of indexes of the unpermuted array
    pub(crate) input_idx: Vec<Value<F>>,
    // input: an unpermuted array
    pub(crate) input: Vec<F>,
    // shuffle_idx: an array of indexes after permuting input
    pub(crate) shuffle_idx: Vec<Value<F>>,
    // shuffle: permuted array from input
    pub(crate) shuffle: Vec<Value<F>>,
}

/// Implement the circuit extension trait for the permutation circuit
impl<F: Field + PrimeField> CircuitExtension<F> for PermutationCircuit<F> {
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let shuffle_chip = ShuffleChip::<F>::construct(config);
        layouter.assign_region(
            || "load inputs",
            |mut region| {
                for (i, (input_idx, input)) in
                    self.input_idx.iter().zip(self.input.iter()).enumerate()
                {
                    region.assign_advice(
                        || "input_idx",
                        shuffle_chip.config.input_0,
                        i,
                        || *input_idx,
                    )?;
                    region.assign_fixed(
                        || "input",
                        shuffle_chip.config.input_1,
                        i,
                        || Value::known(*input),
                    )?;
                    shuffle_chip.config.s_input.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "load shuffles",
            |mut region| {
                for (i, (shuffle_idx, shuffle)) in
                    self.shuffle_idx.iter().zip(self.shuffle.iter()).enumerate()
                {
                    region.assign_advice(
                        || "shuffle_index",
                        shuffle_chip.config.shuffle_0,
                        i,
                        || *shuffle_idx,
                    )?;
                    region.assign_advice(
                        || "shuffle_value",
                        shuffle_chip.config.shuffle_1,
                        i,
                        || *shuffle,
                    )?;
                    shuffle_chip.config.s_shuffle.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Implement the circuit trait for the permutation circuit
impl<F: Field + PrimeField> Circuit<F> for PermutationCircuit<F> {
    // Reuse the config
    type Config = ShuffleConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    // Method: without_witness: return the circuit that has no witnesses
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    // Method: configure: this step is easily implemented by using shuffle API
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let input_idx = meta.advice_column();
        let input = meta.fixed_column();
        let shuffle_idx = meta.advice_column();
        let shuffle = meta.advice_column();
        ShuffleChip::configure(meta, input_idx, input, shuffle_idx, shuffle)
    }

    // Method: synthesize
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let shuffle_chip = ShuffleChip::<F>::construct(config);
        layouter.assign_region(
            || "load inputs",
            |mut region| {
                for (i, (input_idx, input)) in
                    self.input_idx.iter().zip(self.input.iter()).enumerate()
                {
                    region.assign_advice(
                        || "input_idx",
                        shuffle_chip.config.input_0,
                        i,
                        || *input_idx,
                    )?;
                    region.assign_fixed(
                        || "input",
                        shuffle_chip.config.input_1,
                        i,
                        || Value::known(*input),
                    )?;
                    shuffle_chip.config.s_input.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "load shuffles",
            |mut region| {
                for (i, (shuffle_idx, shuffle)) in
                    self.shuffle_idx.iter().zip(self.shuffle.iter()).enumerate()
                {
                    region.assign_advice(
                        || "shuffle_index",
                        shuffle_chip.config.shuffle_0,
                        i,
                        || *shuffle_idx,
                    )?;
                    region.assign_advice(
                        || "shuffle_value",
                        shuffle_chip.config.shuffle_1,
                        i,
                        || *shuffle,
                    )?;
                    shuffle_chip.config.s_shuffle.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Implement a prover proving the permutation circuit using the Inner-Product Argument.
pub struct PermutationProver<C: CurveAffine>
where
    C::Scalar: FromUniformBytes<64>,
{
    params: ParamsIPA<C>,
    pk: ProvingKey<C>,
    circuit: PermutationCircuit<C::Scalar>,
    expected: bool,
}

impl<C: CurveAffine> PermutationProver<C>
where
    C::Scalar: FromUniformBytes<64>,
{
    /// initialize the parameters for the prover
    pub fn new(k: u32, circuit: PermutationCircuit<C::Scalar>, expected: bool) -> Self {
        let params = ParamsIPA::<C>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize verify key");
        Self {
            params,
            pk,
            circuit,
            expected,
        }
    }

    /// Create proof for the permutation circuit
    pub fn create_proof(&mut self) -> Vec<u8> {
        let mut transcript = Blake2bWrite::<Vec<u8>, C, Challenge255<C>>::init(vec![]);
        create_proof::<
            IPACommitmentScheme<C>,
            ProverIPA<'_, C>,
            Challenge255<C>,
            OsRng,
            Blake2bWrite<Vec<u8>, C, Challenge255<C>>,
            PermutationCircuit<C::Scalar>,
        >(
            &self.params,
            &self.pk,
            &[self.circuit.clone()],
            &[&[]],
            OsRng,
            &mut transcript,
        )
        .expect("Fail to create proof.");
        transcript.finalize()
    }

    /// Verify the proof (by comparing the result with expected value)
    pub fn verify(&mut self, proof: Vec<u8>) -> bool {
        let accepted = {
            let strategy = AccumulatorStrategy::new(&self.params);
            let mut transcript = Blake2bRead::<&[u8], C, Challenge255<C>>::init(&proof[..]);
            verify_proof(
                &self.params,
                self.pk.get_vk(),
                strategy,
                &[&[]],
                &mut transcript,
            )
            .map(|strategy| strategy.finalize())
            .expect("Fail to verify proof.")
        };
        accepted == self.expected
    }
}

impl<F: Field + PrimeField> PermutationCircuit<F> {
    /// Create a new permutation circuit with two traces and a random seed
    pub fn new<K, V, const S: usize, const T: usize>(
        input_trace: Vec<(F, TraceRecord<K, V, S, T>)>,
        shuffle_trace: Vec<(F, TraceRecord<K, V, S, T>)>,
    ) -> Self
    where
        K: Base<S>,
        V: Base<T>,
        F: Field + PrimeField + From<K> + From<V>,
    {
        assert_eq!(
            input_trace.len(),
            shuffle_trace.len(),
            "Two input traces are not equal in length."
        );

        let mut rng = rand::thread_rng();
        let mut seeds = [0u64; 5];
        rng.fill(&mut seeds);

        Self {
            input_idx: input_trace
                .clone()
                .into_iter()
                .map(|(x, _)| Value::known(x))
                .collect(),
            input: input_trace
                .clone()
                .into_iter()
                .map(|(_, mut x)| x.compress(seeds))
                .collect(),
            shuffle_idx: shuffle_trace
                .clone()
                .into_iter()
                .map(|(x, _)| Value::known(x))
                .collect(),
            shuffle: shuffle_trace
                .clone()
                .into_iter()
                .map(|(_, mut x)| Value::known(x.compress(seeds)))
                .collect(),
        }
    }
}

// Implement methods for trace records to use for the permutation circuit.
impl<K, V, const S: usize, const T: usize> TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Compress trace elements into a single field element Fp
    pub fn compress<F: From<K> + From<V> + Field + PrimeField>(&mut self, seed: [u64; 5]) -> F {
        let (time_log, stack_depth, instruction, address, value) = self.get_tuple();
        let instruction = match instruction {
            MemoryInstruction::Write => F::ONE,
            MemoryInstruction::Read => F::ZERO,
        };
        // Dot product between trace record and seed
        F::from(time_log) * F::from(seed[0])
            + F::from(stack_depth) * F::from(seed[1])
            + instruction * F::from(seed[2])
            + F::from(address) * F::from(seed[3])
            + F::from(value) * F::from(seed[4])
    }
}

/// Generate an array of successive powers of group generators as indexes
pub fn successive_powers<F: Field + PrimeField>(size: u64) -> Vec<F> {
    let mut curr_power = F::from(1);
    let mut result = vec![];
    for _ in 0..size {
        result.push(curr_power);
        curr_power *= F::MULTIPLICATIVE_GENERATOR;
    }
    result
}

#[cfg(test)]
mod test {

    use crate::{
        base::{Base, B256},
        constraints::permutation_circuit::{PermutationCircuit, PermutationProver},
        machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord},
    };
    use ff::Field;
    use group::ff::PrimeField;
    use halo2_proofs::circuit::Value;
    use halo2curves::pasta::{EqAffine, Fp};
    use rand::{seq::SliceRandom, Rng};
    extern crate alloc;
    use alloc::vec::Vec;

    use super::successive_powers;

    // Randomly create a vector of 2-tuple of trace elements and an index value (for testing)
    fn random_trace<
        K: Base<S>,
        V: Base<T>,
        const S: usize,
        const T: usize,
        F: Field + PrimeField,
    >(
        size: u64,
    ) -> Vec<(F, TraceRecord<K, V, S, T>)> {
        successive_powers::<F>(size)
            .into_iter()
            .map(|i| (i, random_trace_record::<K, V, S, T>()))
            .collect()
    }

    // Randomly create a trace record
    fn random_trace_record<K: Base<S>, V: Base<T>, const S: usize, const T: usize>(
    ) -> TraceRecord<K, V, S, T> {
        let mut rng = rand::thread_rng();
        let instruction = if rng.gen_range(0..2) == 1 {
            MemoryInstruction::Write
        } else {
            MemoryInstruction::Read
        };

        TraceRecord::<K, V, S, T>::new(
            rng.gen_range(0..u64::MAX),
            rng.gen_range(0..u64::MAX),
            instruction,
            K::from(rng.gen_range(u64::MIN..u64::MAX)),
            V::from(rng.gen_range(u64::MIN..u64::MAX)),
        )
    }

    /// Test the circuit function with a randomly generated array
    /// Use Halo2's Prover IPA
    #[test]
    fn test_functionality() {
        // The number of rows cannot exceed 2^k
        const K: u32 = 6;

        let mut rng = rand::thread_rng();
        let mut arr: Vec<(Fp, Fp)> = (1..30)
            .map(|x| (Fp::from(x), Fp::from(rng.gen_range(0..u64::MAX))))
            .collect();
        let input_idx: Vec<Value<Fp>> = arr.iter().map(|&(x, _)| Value::known(x)).collect();
        let input: Vec<Fp> = arr.iter().map(|&(_, x)| x).collect();

        // Random shuffle
        arr.shuffle(&mut rng);

        let shuffle_idx: Vec<Value<Fp>> = arr.iter().map(|&(x, _)| Value::known(x)).collect();
        let shuffle: Vec<Value<Fp>> = arr.iter().map(|&(_, x)| Value::known(x)).collect();

        let circuit = PermutationCircuit {
            input_idx,
            input,
            shuffle_idx,
            shuffle,
        };

        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert!(ipa_prover.verify(proof));
    }

    // Test the functionality of the permutation circuit with a shuffled trace record
    #[test]
    fn check_permutation_with_trace_records() {
        const K: u32 = 6;
        // Number of trace elements in a trace, min = 2^K.
        let trace_size = 50;
        let mut rng = rand::thread_rng();
        let mut trace_buffer = random_trace::<B256, B256, 32, 32, Fp>(trace_size);

        let input_trace = trace_buffer.clone();
        trace_buffer.shuffle(&mut rng);
        let shuffle_trace = trace_buffer.clone();

        let circuit = PermutationCircuit::<Fp>::new(input_trace, shuffle_trace);

        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert!(ipa_prover.verify(proof));
    }

    #[test]
    fn check_trace_record_mapping() {
        // Test 10 times
        for _ in 0..10 {
            let mut record = random_trace_record::<B256, B256, 32, 32>();
            let (time_log, stack_depth, instruction, address, value) = record.get_tuple();
            let instruction = match instruction {
                MemoryInstruction::Write => Fp::ONE,
                MemoryInstruction::Read => Fp::ZERO,
            };
            // Generate a random seed of type [u64; 5]
            let mut rng = rand::thread_rng();
            let mut seeds = [0u64; 5];
            rng.fill(&mut seeds);
            // Dot product between the trace record and the seed.
            let dot_product = Fp::from(time_log) * Fp::from(seeds[0])
                + Fp::from(stack_depth) * Fp::from(seeds[1])
                + instruction * Fp::from(seeds[2])
                + Fp::from(address) * Fp::from(seeds[3])
                + Fp::from(value) * Fp::from(seeds[4]);
            assert_eq!(dot_product, record.compress(seeds));
        }
    }

    #[test]
    #[should_panic]
    fn check_wrong_permutation() {
        const K: u32 = 6;
        // Number of trace elements in a trace, min = 2^K.
        let trace_size = 50;
        let mut rng = rand::thread_rng();
        let mut trace_buffer = random_trace::<B256, B256, 32, 32, Fp>(trace_size);

        let input_trace = trace_buffer.clone();
        trace_buffer.shuffle(&mut rng);
        let mut shuffle_trace = trace_buffer.clone();

        // Tamper shuffle_trace
        shuffle_trace[1].1 = random_trace_record::<B256, B256, 32, 32>();

        let circuit = PermutationCircuit::<Fp>::new(input_trace, shuffle_trace);

        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert!(ipa_prover.verify(proof));
    }

    #[test]
    #[should_panic]
    fn test_inequal_lengths() {
        const K: u32 = 6;
        // Number of trace elements in a trace, min = 2^K.
        let trace_size = 50;
        let mut rng = rand::thread_rng();
        let mut trace_buffer = random_trace::<B256, B256, 32, 32, Fp>(trace_size);
        let input_trace = trace_buffer.clone();
        trace_buffer.shuffle(&mut rng);
        let mut shuffle_trace = trace_buffer.clone();

        // Remove one trace element
        shuffle_trace.pop();

        let circuit = PermutationCircuit::<Fp>::new(input_trace, shuffle_trace);
        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert!(!ipa_prover.verify(proof));
    }
}
