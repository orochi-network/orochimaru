use crate::{
    base::Base,
    constraints::common::CircuitExtension,
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

/// Define a chip struct that implements our instructions.
pub struct ShuffleChip<F: Field + PrimeField> {
    config: ShuffleConfig,
    _marker: PhantomData<F>,
}

/// Define that chip config struct
#[derive(Debug, Clone)]
pub struct ShuffleConfig {
    input_1: Column<Fixed>,
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

    /// Configure the gates
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input_1: Column<Fixed>,
        shuffle_1: Column<Advice>,
    ) -> ShuffleConfig {
        let s_shuffle = meta.complex_selector();
        let s_input = meta.complex_selector();
        meta.shuffle("two traces are permutation of each other", |meta| {
            let s_input = meta.query_selector(s_input);
            let s_shuffle = meta.query_selector(s_shuffle);
            let input_1 = meta.query_fixed(input_1, Rotation::cur());
            let shuffle_1 = meta.query_advice(shuffle_1, Rotation::cur());
            vec![(s_input * input_1, s_shuffle * shuffle_1)]
        });

        ShuffleConfig {
            input_1,
            shuffle_1,
            s_input,
            s_shuffle,
        }
    }
}

/// Define the permutatioin circuit for the project
#[derive(Default, Clone, Debug)]
pub struct PermutationCircuit<F: Field + PrimeField> {
    // input: an unpermuted array
    pub(crate) input: Vec<F>,
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
                for (i, input) in self.input.iter().enumerate() {
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
                for (i, shuffle) in self.shuffle.iter().enumerate() {
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
        let input = meta.fixed_column();
        let shuffle = meta.advice_column();
        ShuffleChip::configure(meta, input, shuffle)
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
                for (i, input) in self.input.iter().enumerate() {
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
                for (i, shuffle) in self.shuffle.iter().enumerate() {
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
        input_trace: Vec<TraceRecord<K, V, S, T>>,
        shuffle_trace: Vec<TraceRecord<K, V, S, T>>,
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
            input: input_trace
                .clone()
                .into_iter()
                .map(|mut x| x.compress(seeds))
                .collect(),
            shuffle: shuffle_trace
                .clone()
                .into_iter()
                .map(|mut x| Value::known(x.compress(seeds)))
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

#[cfg(test)]
mod tests {

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

    // Randomly create a vector of 2-tuple of trace elements and an index value (for testing)
    fn random_trace<
        K: Base<S>,
        V: Base<T>,
        const S: usize,
        const T: usize,
        F: Field + PrimeField,
    >(
        size: u64,
    ) -> Vec<TraceRecord<K, V, S, T>> {
        (0..size)
            .map(|_| random_trace_record::<K, V, S, T>())
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
        let input: Vec<Fp> = arr.iter().map(|&(_, x)| x).collect();

        // Random shuffle
        arr.shuffle(&mut rng);

        let shuffle: Vec<Value<Fp>> = arr.iter().map(|&(_, x)| Value::known(x)).collect();

        let circuit = PermutationCircuit { input, shuffle };

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
        // Test 10 times so that the trace will always have Read and Write instructions
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
        shuffle_trace[1] = random_trace_record::<B256, B256, 32, 32>();

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
