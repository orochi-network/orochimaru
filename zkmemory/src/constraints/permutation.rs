use core::marker::PhantomData;
use ff::PrimeField;
use group::ff::{Field, FromUniformBytes};
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
use crate::{
    base::Base,
    machine::{MemoryInstruction, TraceRecord},
};
use alloc::{vec, vec::Vec};

/// Define a chip struct that implements our instructions.
struct ShuffleChip<F: Field + PrimeField> {
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
    //^ Construct a permutation chip using the config
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
pub struct PermutationCircuit<F: Field + PrimeField> {
    //^ input_idx: an array of indexes of the unpermuted array
    input_idx: Vec<Value<F>>,
    //^ input: an unpermuted array
    input: Vec<F>,
    //^ shuffle_idx: an array of indexes after permuting input
    shuffle_idx: Vec<Value<F>>,
    //^ shuffle: permuted array from input
    shuffle: Vec<Value<F>>,
}

impl<F: Field + PrimeField> Circuit<F> for PermutationCircuit<F> {
    //* Reuse the config
    type Config = ShuffleConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    //* Method: without_witness: return the circuit that has no witnesses
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    //* Method: configure: this step is easily implemented by using shuffle API
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let input_idx = meta.advice_column();
        let input = meta.fixed_column();
        let shuffle_idx = meta.advice_column();
        let shuffle = meta.advice_column();
        ShuffleChip::configure(meta, input_idx, input, shuffle_idx, shuffle)
    }

    //* Method: synthesize
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

impl<F: Field + PrimeField> PermutationCircuit<F> {
    /// Create a new permutation circuit with two traces and a random seed
    pub fn new<K, V, const S: usize, const T: usize>(
        input_trace: Vec<(u64, TraceRecord<K, V, S, T>)>,
        shuffle_trace: Vec<(u64, TraceRecord<K, V, S, T>)>,
        seeds: [F; 5],
    ) -> Self
    where
        K: Base<S>,
        V: Base<T>,
        F: Field + PrimeField + From<K> + From<V>,
    {
        Self {
            input_idx: input_trace
                .clone()
                .into_iter()
                .map(|(x, _)| Value::known(F::from(x)))
                .collect(),
            input: input_trace
                .clone()
                .into_iter()
                .map(|(_, mut x)| x.compress(seeds))
                .collect(),
            shuffle_idx: shuffle_trace
                .clone()
                .into_iter()
                .map(|(x, _)| Value::known(F::from(x)))
                .collect(),
            shuffle: shuffle_trace
                .clone()
                .into_iter()
                .map(|(_, mut x)| Value::known(x.compress(seeds)))
                .collect(),
        }
    }
}

/// Implement methods for trace records to use for the permutation circuit.
impl<K, V, const S: usize, const T: usize> TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Compress trace elements into a single field element Fp
    pub fn compress<F: From<K> + From<V> + Field + PrimeField>(&mut self, seed: [F; 5]) -> F {
        let (time_log, stack_depth, instruction, address, value) = self.get_tuple();
        let instruction = match instruction {
            MemoryInstruction::Write => F::ONE,
            MemoryInstruction::Read => F::ZERO,
        };
        // Dot product between trace record and seed
        F::from(time_log) * seed[0]
            + F::from(stack_depth) * seed[1]
            + instruction * seed[2]
            + F::from(address) * seed[3]
            + F::from(value) * seed[4]
    }
}

/// Use quicksort to sort the trace in order of ascending time_log
pub fn sort_chronologically<K, V, const S: usize, const T: usize>(
    mut trace: Vec<(u64, TraceRecord<K, V, S, T>)>,
) -> Vec<(u64, TraceRecord<K, V, S, T>)>
where
    K: Base<S>,
    V: Base<T>,
{
    if trace.len() <= 1 {
        return trace;
    }

    let pivot = trace.remove(0);
    let mut left = vec![];
    let mut right = vec![];

    for item in trace {
        if item.1.get_tuple().0 <= pivot.1.get_tuple().0 {
            left.push(item);
        } else {
            right.push(item);
        }
    }

    let mut sorted_left = sort_chronologically(left);
    let mut sorted_right = sort_chronologically(right);

    sorted_left.push(pivot);
    sorted_left.append(&mut sorted_right);

    sorted_left
}
#[cfg(test)]
mod test {

    use crate::{
        base::{Base, B256},
        constraints::permutation::{PermutationCircuit, PermutationProver},
        machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord},
    };
    use ff::Field;
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use halo2curves::pasta::{EqAffine, Fp};
    use rand::{seq::SliceRandom, Rng};
    extern crate alloc;
    use alloc::{vec, vec::Vec};

    // ~ Randomly create a vector of 2-tuple of trace elements and an index value (for testing)
    fn random_trace<K: Base<S>, V: Base<T>, const S: usize, const T: usize>(
        size: u64,
    ) -> Vec<(u64, TraceRecord<K, V, S, T>)> {
        (1..size)
            .map(|i| (i, random_trace_record::<K, V, S, T>()))
            .collect()
    }

    // ~ Randomly create a trace record
    fn random_trace_record<K: Base<S>, V: Base<T>, const S: usize, const T: usize>(
    ) -> TraceRecord<K, V, S, T> {
        let mut rng = rand::thread_rng();
        let instruction = if rng.gen() {
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

    /// Test the circuit function with a simple array
    /// Use Halo2's MockProver to prove the circuit
    /// Currently using a randomly generated array
    #[test]
    fn test_functionality() {
        const K: u32 = 8;

        let mut rng = rand::thread_rng();

        let mut arr = {
            let mut arr: Vec<(u64, Fp)> = vec![];
            for x in 1..30u64 {
                arr.push((x, Fp::from(rng.gen_range(0..u64::MAX))));
            }
            arr
        };

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
        assert!(ipa_prover.verify(proof));
    }

    // Test the functionality of the permutation circuit with a shuffled trace record
    #[test]
    fn check_permutation_with_trace_records() {
        const K: u32 = 6;
        // Number of trace elements in a trace, min = 2^K.
        let trace_size = 50;

        let mut rng = rand::thread_rng();
        let mut trace = random_trace::<B256, B256, 32, 32>(trace_size);

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
        let input: Vec<Fp> = trace.iter().map(|&(_, mut x)| x.compress(seeds)).collect();

        trace.shuffle(&mut rng);

        // Get the index and the value after shuffle
        let shuffle_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();
        let shuffle: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(_, mut x)| Value::known(x.compress(seeds)))
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
        assert!(ipa_prover.verify(proof));
    }

    #[test]
    fn check_trace_record_mapping() {
        let mut record = random_trace_record::<B256, B256, 32, 32>();
        let (time_log, stack_depth, instruction, address, value) = record.get_tuple();
        let instruction = match instruction {
            MemoryInstruction::Write => Fp::ONE,
            MemoryInstruction::Read => Fp::ZERO,
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
        assert_eq!(dot_product, record.compress(seeds));
    }

    #[test]
    #[should_panic]
    fn check_wrong_permutation() {
        const K: u32 = 4;
        let mut rng = rand::thread_rng();
        let mut trace = [
            (1, random_trace_record::<B256, B256, 32, 32>()),
            (2, random_trace_record::<B256, B256, 32, 32>()),
            (3, random_trace_record::<B256, B256, 32, 32>()),
            (4, random_trace_record::<B256, B256, 32, 32>()),
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
        let input: Vec<Fp> = trace.iter().map(|&(_, mut x)| x.compress(seeds)).collect();

        trace.shuffle(&mut rng);

        let shuffle_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();

        let mut shuffle: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(_, mut x)| Value::known(x.compress(seeds)))
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
        assert!(ipa_prover.verify(proof));
    }
}