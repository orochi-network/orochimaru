use core::marker::PhantomData;
use group::ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
extern crate alloc;
use alloc::{vec, vec::Vec};

// Define a chip struct that implements our instructions.
struct ShuffleChip<F: Field> {
    config: ShuffleConfig,
    _marker: PhantomData<F>,
}

// Define that chip config struct
#[derive(Debug, Clone)]
struct ShuffleConfig {
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

// Define the circuit for the project
#[derive(Default)]
struct PermutationCircuit<F: Field> {
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

//TODO: Inspect PSE code to implement a non-mock prover proving the permutation circuit.
// fn prover() -> () {

// }

#[cfg(test)]
mod test {
    use crate::base::{Base, B256};
    use crate::constraints::permutation::PermutationCircuit;
    use crate::machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord};
    use ff::Field;
    use halo2_proofs::circuit::Value;
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use rand::seq::SliceRandom;
    use rand::Rng;
    extern crate alloc;
    use alloc::{vec, vec::Vec};

    // Generate a trace record
    fn generate_trace_record() -> TraceRecord<B256, B256, 32, 32> {
        let mut rng = rand::thread_rng();
        let instruction = if rng.gen() {
            MemoryInstruction::Read
        } else {
            MemoryInstruction::Write
        };

        TraceRecord::<B256, B256, 32, 32>::new(
            rng.gen_range(0..u64::MAX),
            rng.gen_range(0..u64::MAX),
            instruction,
            B256::from(rng.gen_range(i32::MIN..i32::MAX)),
            B256::from(rng.gen_range(i32::MIN..i32::MAX)),
        )
    }

    //TODO: Implement a function that map trace record elements to a single element in Fr, Fq, etc.
    fn compress_trace_elements<K: Base<S>, V: Base<T>, const S: usize, const T: usize>(
        trace_record: TraceRecord<K, V, S, T>,
        seed: [Fp; 5],
    ) -> Fp
    where
        halo2curves::pasta::Fp: From<K> + From<V>,
    {
        let (time_log, stack_depth, instruction, address, value) = trace_record.get_tuple();
        let instruction = match instruction {
            MemoryInstruction::Read => Fp::ONE,
            MemoryInstruction::Write => Fp::ZERO,
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
    /// Currently using a fixed array
    //TODO: Use a random array
    #[test]
    fn test_functionality() {
        const K: u32 = 8;
        let input_0 = [1, 2, 3, 4, 5, 6, 7, 8]
            .map(|e: u64| Value::known(Fp::from(e)))
            .to_vec();
        let input_1 = [1, 2, 4, 8, 16, 32, 64, 128].map(Fp::from).to_vec();
        let shuffle_0 = [1, 3, 5, 2, 4, 6, 8, 7]
            .map(|e: u64| Value::known(Fp::from(e)))
            .to_vec();
        let shuffle_1 = [1, 4, 16, 2, 8, 32, 128, 64]
            .map(|e: u64| Value::known(Fp::from(e)))
            .to_vec();
        let circuit = PermutationCircuit {
            input_idx: input_0,
            input: input_1,
            shuffle_idx: shuffle_0,
            shuffle: shuffle_1,
        };
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    //TODO: implement this function (derive a method to map trace record elements into a single element)
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
        let mut seed = [Fp::ZERO; 5];
        for i in 0..5 {
            seed[i] = Fp::from(rng.gen_range(0..u64::MAX));
        }

        // Get the index and the value before shuffle
        let trace_idx: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();
        let trace_value: Vec<Fp> = trace
            .iter()
            .map(|&(_, x)| compress_trace_elements(x, seed))
            .collect();

        trace.shuffle(&mut rng);

        // Get the index and the value after shuffle
        let trace_idx_after: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(x, _)| Value::known(Fp::from(x)))
            .collect();
        let trace_value_after: Vec<Value<Fp>> = trace
            .iter()
            .map(|&(_, x)| Value::known(compress_trace_elements(x, seed)))
            .collect();

        let circuit = PermutationCircuit {
            input_idx: trace_idx,
            input: trace_value,
            shuffle_idx: trace_idx_after,
            shuffle: trace_value_after,
        };
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
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
        let mut seed = [Fp::ZERO; 5];
        for i in 0..5 {
            seed[i] = Fp::from(rng.gen_range(0..u64::MAX));
        }
        // Dot product between the trace record and the seed.
        let dot_product = Fp::from(time_log) * seed[0]
            + Fp::from(stack_depth) * seed[1]
            + instruction * seed[2]
            + Fp::from(address) * seed[3]
            + Fp::from(value) * seed[4];
        assert_eq!(dot_product, compress_trace_elements(record, seed));
    }
}
