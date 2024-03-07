extern crate alloc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::{iter::once, marker::PhantomData};
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Fixed, Selector};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};
use rand::thread_rng;
extern crate std;

use crate::base::B256;
use crate::constraints::lexicographic_ordering::Queries;
use crate::machine::TraceRecord;

use super::chronically_ordering::{OriginalMemoryCircuit, OriginalMemoryConfig};
use super::common::CircuitExtension;
use super::gadgets::{equal_value, BinaryConfigure, Table};
use super::lexicographic_ordering::{GreaterThanConfigure, SortedTraceRecord};
use super::{
    lexicographic_ordering::{
        LookUpTables, SortedMemoryCircuit, SortedMemoryConfig, TraceRecordWitnessTable,
    },
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
    fn construct(
        lexicographic_ordering_config: SortedMemoryConfig<F>,
        permutation_config: ShuffleConfig,
        chronically_ordering_config: OriginalMemoryConfig<F>,
    ) -> Self {
        Self {
            chronically_ordering_config,
            lexicographic_ordering_config,
            permutation_config,
            _marker: PhantomData,
        }
    }
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
            sorted_trace_record.push(SortedTraceRecord::<F>::from(trace));
        }
        let mut original_trace_record = vec![];
        for (_, trace) in self.input.clone() {
            original_trace_record.push(SortedTraceRecord::<F>::from(trace));
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
            size64_table: Table::<64>::construct(meta),
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
