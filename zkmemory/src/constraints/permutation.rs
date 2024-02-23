use core::marker::PhantomData;
use ff::FromUniformBytes;
use group::ff::Field;
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
use rand_core::OsRng;
extern crate alloc;
use alloc::{vec, vec::Vec};

/// Define a chip struct that implements our instructions.
struct ShuffleChip<F: Field> {
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

impl<F: Field> ShuffleChip<F> {
    // Construct a permutation chip using the config
    fn construct(config: ShuffleConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
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
#[derive(Default, Clone)]
pub struct PermutationCircuit<F: Field> {
    // input_idx: an array of indexes of the unpermuted array
    input_idx: Vec<Value<F>>,
    // input: an unpermuted array
    input: Vec<F>,
    // shuffle_idx: an array of indexes after permuting input
    shuffle_idx: Vec<Value<F>>,
    // shuffle: permuted array from input
    shuffle: Vec<Value<F>>,
}

impl<F: Field> Circuit<F> for PermutationCircuit<F> {
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

/// Implement a non-mock prover proving the permutation circuit using the Inner-Product Argument.
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
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<IPACommitmentScheme<C>, ProverIPA<'_, C>, _, _, _, _>(
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
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
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

#[cfg(test)]
mod test {
    use crate::base::{Base, B256};
    use crate::constraints::permutation::{PermutationCircuit, PermutationProver};
    use crate::machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord};
    use ff::Field;
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use halo2curves::pasta::{EqAffine, Fp};
    use rand::{seq::SliceRandom, Rng};
    extern crate alloc;
    use alloc::{vec, vec::Vec};

    // Generate a trace record
    fn generate_trace_record() -> TraceRecord<B256, B256, 32, 32> {
        let mut rng = rand::thread_rng();
        let instruction = if rng.gen() {
            MemoryInstruction::Write
        } else {
            MemoryInstruction::Read
        };

        TraceRecord::<B256, B256, 32, 32>::new(
            rng.gen_range(0..u64::MAX),
            rng.gen_range(0..u64::MAX),
            instruction,
            B256::from(rng.gen_range(i32::MIN..i32::MAX)),
            B256::from(rng.gen_range(i32::MIN..i32::MAX)),
        )
    }

    // Map trace record elements to a single element in Fr, Fq, etc.
    fn compress_trace_elements<K: Base<S>, V: Base<T>, const S: usize, const T: usize>(
        trace_record: TraceRecord<K, V, S, T>,
        seed: [Fp; 5],
    ) -> Fp
    where
        halo2curves::pasta::Fp: From<K> + From<V>,
    {
        let (time_log, stack_depth, instruction, address, value) = trace_record.get_tuple();
        let instruction = match instruction {
            MemoryInstruction::Read => Fp::ZERO,
            MemoryInstruction::Write => Fp::ONE,
        };
        // Dot product between trace record and seed
        Fp::from(time_log) * seed[0]
            + Fp::from(stack_depth) * seed[1]
            + instruction * seed[2]
            + Fp::from(address) * seed[3]
            + Fp::from(value) * seed[4]
    }

    /// Test the circuit function with a simple array
    /// Use Halo2's MockProver to prove the circuit
    /// Currently using a randomly generated array
    #[test]
    fn test_functionality() {
        const K: u32 = 8;

        let mut rng = rand::thread_rng();

        let mut arr = [
            (1, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (2, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (3, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (4, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (5, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (6, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (7, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
            (8, Fp::from(rng.gen_range(0..u64::MAX) as u64)),
        ];

        // Generate seed
        let seeds = [Fp::ZERO; 5];
        for _seed in seeds {
            let _seed = Fp::from(rng.gen_range(0..u64::MAX));
        }

        let input_idx: Vec<Value<Fp>> = arr
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();

        let input: Vec<Fp> = arr.iter().map(|&(_, x)| x).collect();

        arr.shuffle(&mut rng);

        let shuffle_idx: Vec<Value<Fp>> = arr
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();

        let shuffle: Vec<Value<Fp>> = arr.iter().map(|&(_, x)| Value::known(x)).collect();

        let circuit = PermutationCircuit {
            input_idx,
            input,
            shuffle_idx,
            shuffle,
        };

        // Test with mock prover
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert_eq!(ipa_prover.verify(proof), true);
    }

    // Test the functionality of the permutation circuit with a shuffled trace record
    #[test]
    fn check_permutation_with_trace_records() {
        const K: u32 = 4;
        let mut rng = rand::thread_rng();
        let mut trace = [
            (1, generate_trace_record()),
            (2, generate_trace_record()),
            (3, generate_trace_record()),
            (4, generate_trace_record()),
        ];

        // Generate seed
        let seeds = [Fp::ZERO; 5];
        for _seed in seeds {
            let _seed = Fp::from(rng.gen_range(0..u64::MAX));
        }

        // Get the index and the value before shuffle
        let input_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();
        let input: Vec<Fp> = trace
            .iter()
            .map(|&(_, x)| compress_trace_elements(x, seeds))
            .collect();

        trace.shuffle(&mut rng);

        // Get the index and the value after shuffle
        let shuffle_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();
        let shuffle: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(_, x)| Value::known(compress_trace_elements(x, seeds)))
            .collect();

        let circuit = PermutationCircuit {
            input_idx,
            input,
            shuffle_idx,
            shuffle,
        };

        // Test with mock prover
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert_eq!(ipa_prover.verify(proof), true);
    }

    #[test]
    fn check_trace_record_mapping() {
        let record = generate_trace_record();
        let (time_log, stack_depth, instruction, address, value) = record.get_tuple();
        let instruction = match instruction {
            MemoryInstruction::Read => Fp::ONE,
            MemoryInstruction::Write => Fp::ZERO,
        };
        // Generate a random seed of type [u64; 5]
        let mut rng = rand::thread_rng();
        let seeds = [Fp::ZERO; 5];
        for _seed in seeds {
            let _seed = Fp::from(rng.gen_range(0..u64::MAX));
        }
        // Dot product between the trace record and the seed.
        let dot_product = Fp::from(time_log) * seeds[0]
            + Fp::from(stack_depth) * seeds[1]
            + instruction * seeds[2]
            + Fp::from(address) * seeds[3]
            + Fp::from(value) * seeds[4];
        assert_eq!(dot_product, compress_trace_elements(record, seeds));
    }

    #[test]
    #[should_panic]
    fn check_wrong_permutation() {
        const K: u32 = 4;
        let mut rng = rand::thread_rng();
        let mut trace = [
            (1, generate_trace_record()),
            (2, generate_trace_record()),
            (3, generate_trace_record()),
            (4, generate_trace_record()),
        ];

        // Generate seed
        let seeds = [Fp::ZERO; 5];
        for _seed in seeds {
            let _seed = Fp::from(rng.gen_range(0..u64::MAX));
        }

        // Get the index and the value before shuffle
        let input_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();
        let input: Vec<Fp> = trace
            .iter()
            .map(|&(_, x)| compress_trace_elements(x, seeds))
            .collect();

        trace.shuffle(&mut rng);

        let shuffle_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();

        let mut shuffle: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(_, x)| Value::known(compress_trace_elements(x, seeds)))
            .collect();

        // Tamper shuffle
        shuffle[0] = Value::known(Fp::from(rng.gen_range(0..u64::MAX)));

        let circuit = PermutationCircuit {
            input_idx,
            input,
            shuffle_idx,
            shuffle,
        };

        // Test with mock prover
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        // Test with IPA prover
        let mut ipa_prover = PermutationProver::<EqAffine>::new(K, circuit, true);
        let proof = ipa_prover.create_proof();
        assert_eq!(ipa_prover.verify(proof), true);
    }
}
