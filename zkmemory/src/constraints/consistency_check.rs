extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};
use rand::thread_rng;
extern crate std;
use crate::base::B256;
use crate::machine::TraceRecord;

use super::chronically_ordering::{OriginalMemoryCircuit, OriginalMemoryConfig};
use super::common::CircuitExtension;
use super::gadgets::Table;
use super::gadgets::{ConvertedTraceRecord, LookUpTables, TraceRecordWitnessTable};
use super::{
    lexicographic_ordering::{SortedMemoryCircuit, SortedMemoryConfig},
    permutation::{PermutationCircuit, ShuffleChip, ShuffleConfig},
};

/// Config for consistency check circuit
#[derive(Debug, Clone)]
pub struct ConsistencyConfig<F: Field + PrimeField> {
    chronically_ordering_config: OriginalMemoryConfig<F>,
    lexicographic_ordering_config: SortedMemoryConfig<F>,
    permutation_config: ShuffleConfig,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> ConsistencyConfig<F> {
    // fn construct(
    //     lexicographic_ordering_config: SortedMemoryConfig<F>,
    //     permutation_config: ShuffleConfig,
    //     chronically_ordering_config: OriginalMemoryConfig<F>,
    // ) -> Self {
    //     Self {
    //         chronically_ordering_config,
    //         lexicographic_ordering_config,
    //         permutation_config,
    //         _marker: PhantomData,
    //     }
    // }
    fn configure(
        meta: &mut ConstraintSystem<F>,
        input_0: Column<Advice>,
        input_1: Column<Fixed>,
        shuffle_0: Column<Advice>,
        shuffle_1: Column<Advice>,
        original_trace_record: TraceRecordWitnessTable<F>,
        sorted_trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        Self {
            chronically_ordering_config: OriginalMemoryConfig::<F>::configure(
                meta,
                original_trace_record,
                lookup_tables,
                alpha_power.clone(),
            ),

            lexicographic_ordering_config: SortedMemoryConfig::<F>::configure(
                meta,
                sorted_trace_record,
                lookup_tables,
                alpha_power,
            ),
            permutation_config: ShuffleChip::<F>::configure(
                meta, input_0, input_1, shuffle_0, shuffle_1,
            ),
            _marker: PhantomData,
        }
    }
}

/// Define the memory consistency circuit
#[derive(Default, Clone, Debug)]
pub struct MemoryConsistencyCircuit<F: Field + PrimeField + From<B256> + From<B256>> {
    /// input_trace: Array of trace records before sorting along with its indexes
    input: Vec<(F, TraceRecord<B256, B256, 32, 32>)>,
    /// shuffle_trace: Array after permutations
    shuffle: Vec<(F, TraceRecord<B256, B256, 32, 32>)>,
}

/// Implement the circuit extension for memory consistency circuit
impl<F: Field + PrimeField + From<B256> + From<B256>> CircuitExtension<F>
    for MemoryConsistencyCircuit<F>
{
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let permutation_tuple = PermutationCircuit::<F>::new::<B256, B256, 32, 32>(
            self.input.clone(),
            self.shuffle.clone(),
        );
        let (input_idx, input, shuffle_idx, shuffle) = permutation_tuple.get_tuple();
        let permutation_circuit = PermutationCircuit {
            input_idx,
            input,
            shuffle_idx,
            shuffle,
        };
        permutation_circuit.synthesize_with_layouter(config.permutation_config, layouter)?;
        let mut sorted_trace_record = vec![];
        for (_, trace) in self.shuffle.clone() {
            sorted_trace_record.push(ConvertedTraceRecord::<F>::from(trace));
        }
        let mut original_trace_record = vec![];
        for (_, trace) in self.input.clone() {
            original_trace_record.push(ConvertedTraceRecord::<F>::from(trace));
        }
        let original_ordering_circuit = OriginalMemoryCircuit {
            original_trace_record,
            _marker: PhantomData,
        };
        let lexicographic_ordering_circuit = SortedMemoryCircuit {
            sorted_trace_record,
            _marker: PhantomData,
        };
        lexicographic_ordering_circuit
            .synthesize_with_layouter(config.lexicographic_ordering_config, layouter)?;
        original_ordering_circuit
            .synthesize_with_layouter(config.chronically_ordering_config, layouter)?;
        Ok(())
    }
}

impl<F: Field + PrimeField + From<B256> + From<B256>> Circuit<F> for MemoryConsistencyCircuit<F> {
    type Config = ConsistencyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();
    // Method: without_witness: return the circuit that has no witnesses
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    // configure the circuit
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rng = thread_rng();

        // the elements of the trace record
        let original_trace_record = TraceRecordWitnessTable::<F>::new(meta);
        let sorted_trace_record = TraceRecordWitnessTable::<F>::new(meta);

        // lookup tables
        let lookup_tables = LookUpTables {
            size256_table: Table::<256>::construct(meta),
            size40_table: Table::<40>::construct(meta),
            size2_table: Table::<2>::construct(meta),
        };
        // the random challenges
        let alpha = Expression::Constant(F::random(rng));
        let mut tmp = Expression::Constant(F::ONE);
        let mut alpha_power: Vec<Expression<F>> = vec![tmp.clone()];
        for _ in 0..40 {
            tmp = tmp * alpha.clone();
            alpha_power.push(tmp.clone());
        }
        let input_idx = meta.advice_column();
        let input = meta.fixed_column();
        let shuffle_idx = meta.advice_column();
        let shuffle = meta.advice_column();
        Self::Config::configure(
            meta,
            input_idx,
            input,
            shuffle_idx,
            shuffle,
            original_trace_record,
            sorted_trace_record,
            lookup_tables,
            alpha_power,
        )
    }

    /// Forward to the synthesize_with_layouter method
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.synthesize_with_layouter(config, &mut layouter)
    }
}

#[cfg(test)]
mod test {
    use super::std::println;

    use crate::constraints::gadgets::ConvertedTraceRecord;
    use crate::machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord};
    extern crate alloc;
    use crate::base::{Base, B256};
    use crate::constraints::permutation::successive_powers;
    use alloc::{vec, vec::Vec};
    use ff::{Field, PrimeField};
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;

    use super::MemoryConsistencyCircuit;

    // Sort the trace by time_log as key
    fn sort_chronologically<K, V, const S: usize, const T: usize, F>(
        trace: Vec<(F, TraceRecord<K, V, S, T>)>,
    ) -> Vec<(F, TraceRecord<K, V, S, T>)>
    where
        K: Base<S>,
        V: Base<T>,
        F: Field + PrimeField,
    {
        let mut buffer = trace;
        buffer.sort_by(|a, b| a.1.get_tuple().0.cmp(&b.1.get_tuple().0));
        buffer
    }

    // Outputs the trace with their respective indexes
    fn trace_with_index<
        K: Base<S>,
        V: Base<T>,
        const S: usize,
        const T: usize,
        F: Field + PrimeField,
    >(
        trace: Vec<TraceRecord<K, V, S, T>>,
    ) -> Vec<(F, TraceRecord<K, V, S, T>)> {
        let indexes = successive_powers::<F>(trace.len() as u64);
        indexes
            .into_iter()
            .zip(trace.into_iter())
            .collect::<Vec<(F, TraceRecord<K, V, S, T>)>>()
    }

    // Common test function to build and check the consistency circuit
    fn build_and_test_circuit(trace: Vec<TraceRecord<B256, B256, 32, 32>>, k: u32) {
        // Initially, the trace is sorted by address-time
        let trace = trace_with_index::<B256, B256, 32, 32, Fp>(trace);

        // Sort this trace in timelog
        let sorted_trace = sort_chronologically::<B256, B256, 32, 32, Fp>(trace.clone());

        let circuit = MemoryConsistencyCircuit::<Fp> {
            input: sorted_trace.clone(),
            shuffle: trace.clone(),
        };

        let prover = MockProver::run(k, &circuit, vec![]).expect("What");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    #[should_panic]
    fn invalid_read_in_time_0() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(1),
        );

        build_and_test_circuit(vec![trace_0], 10);
    }

    #[test]
    fn test_one_trace() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        build_and_test_circuit(vec![trace_0], 10);
    }

    #[test]
    #[should_panic]
    fn test_read_unwritten_address() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Read,
            B256::from(0x20),
            B256::from(0),
        );

        build_and_test_circuit(vec![trace_0, trace_1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_read() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(9),
        );

        build_and_test_circuit(vec![trace_0, trace_1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_starting_time() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            6,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        build_and_test_circuit(vec![trace_0], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_initial_ordering() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            2,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(5),
        );

        build_and_test_circuit(vec![trace_2, trace_0, trace_1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_permutation() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            2,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(5),
        );

        // Initially, the trace is sorted by address-time
        let trace = trace_with_index::<B256, B256, 32, 32, Fp>(vec![trace_0, trace_1, trace_2]);

        // Sort this trace in timelog
        let mut sorted_trace = sort_chronologically::<B256, B256, 32, 32, Fp>(trace.clone());
        // Tamper the permutation
        sorted_trace.swap(0, 1);

        let circuit = MemoryConsistencyCircuit::<Fp> {
            input: sorted_trace.clone(),
            shuffle: trace.clone(),
        };

        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_basic_read_write() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            4,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(1),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(2),
        );

        let trace_3 = TraceRecord::<B256, B256, 32, 32>::new(
            2,
            0,
            MemoryInstruction::Read,
            B256::from(0x20),
            B256::from(0x2),
        );

        let trace_4 = TraceRecord::<B256, B256, 32, 32>::new(
            7,
            0,
            MemoryInstruction::Write,
            B256::from(0x6f),
            B256::from(3),
        );

        build_and_test_circuit(vec![trace_0, trace_1, trace_2, trace_3, trace_4], 10);
    }
}
