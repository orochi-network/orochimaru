//! The grand circuit for checking memory consistency
extern crate alloc;
use crate::{
    base::B256,
    constraints::{
        common::CircuitExtension,
        gadgets::{ConvertedTraceRecord, LookUpTables, Table, TraceRecordWitnessTable},
        original_memory_circuit::{OriginalMemoryCircuit, OriginalMemoryConfig},
        permutation_circuit::{PermutationCircuit, ShuffleChip, ShuffleConfig},
        sorted_memory_circuit::{SortedMemoryCircuit, SortedMemoryConfig},
    },
    machine::TraceRecord,
};
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed},
};
use rand::thread_rng;

/// Config for consistency check circuit
#[derive(Debug, Clone)]
pub(crate) struct ConsistencyConfig<F: Field + PrimeField> {
    // the config of the original memory
    pub(crate) original_memory_config: OriginalMemoryConfig<F>,
    // the config of the sorted memory
    pub(crate) sorted_memory_config: SortedMemoryConfig<F>,
    // the config of permutation check
    pub(crate) permutation_config: ShuffleConfig,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> ConsistencyConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        shuffle_input: (Column<Fixed>, Column<Advice>),
        original_trace_record: TraceRecordWitnessTable<F>,
        sorted_trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        Self {
            original_memory_config: OriginalMemoryConfig::<F>::configure(
                meta,
                original_trace_record,
                lookup_tables,
                alpha_power.clone(),
            ),

            sorted_memory_config: SortedMemoryConfig::<F>::configure(
                meta,
                sorted_trace_record,
                lookup_tables,
                alpha_power,
            ),
            permutation_config: ShuffleChip::<F>::configure(meta, shuffle_input.0, shuffle_input.1),
            _marker: PhantomData,
        }
    }
}

/// Define the memory consistency circuit
#[derive(Default, Clone, Debug)]
pub(crate) struct MemoryConsistencyCircuit<F: Field + PrimeField + From<B256>> {
    /// input_trace: Array of trace records before sorting (sorted by time_log)
    pub(crate) input: Vec<TraceRecord<B256, B256, 32, 32>>,
    /// shuffle_trace: Array after permutations (sorted by address and time_log)
    pub(crate) shuffle: Vec<TraceRecord<B256, B256, 32, 32>>,
    /// A marker since these fields do not use trait F
    pub(crate) marker: PhantomData<F>,
}

/// Implement the circuit extension for memory consistency circuit
impl<F: Field + PrimeField + From<B256>> CircuitExtension<F> for MemoryConsistencyCircuit<F> {
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let permutation_circuit = PermutationCircuit::<F>::new::<B256, B256, 32, 32>(
            self.input.clone(),
            self.shuffle.clone(),
        );
        permutation_circuit.synthesize_with_layouter(config.permutation_config, layouter)?;
        let mut sorted_trace_record = vec![];
        for trace in self.shuffle.clone() {
            sorted_trace_record.push(ConvertedTraceRecord::<F>::from(trace));
        }
        let mut original_trace_record = vec![];
        for trace in self.input.clone() {
            original_trace_record.push(ConvertedTraceRecord::<F>::from(trace));
        }
        let original_memory_circuit = OriginalMemoryCircuit {
            original_trace_record,
            _marker: PhantomData,
        };
        let sorted_memory_circuit = SortedMemoryCircuit {
            sorted_trace_record,
            _marker: PhantomData,
        };
        sorted_memory_circuit.synthesize_with_layouter(config.sorted_memory_config, layouter)?;
        original_memory_circuit
            .synthesize_with_layouter(config.original_memory_config, layouter)?;
        Ok(())
    }
}

impl<F: Field + PrimeField + From<B256>> Circuit<F> for MemoryConsistencyCircuit<F> {
    type Config = ConsistencyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

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
        let input = meta.fixed_column();
        let shuffle = meta.advice_column();
        Self::Config::configure(
            meta,
            (input, shuffle),
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
