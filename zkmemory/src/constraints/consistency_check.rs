extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Fixed, Selector};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
extern crate std;

use crate::base::{Base, B256};
use crate::machine::{MemoryInstruction, TraceRecord};

use super::common::CircuitExtension;
use super::gadgets::BinaryConfigure;
use super::lexicographic_ordering::SortedTraceRecord;
use super::{lexicographic_ordering, permutation};
use super::{
    lexicographic_ordering::{
        LookUpTables, SortedMemoryCircuit, SortedMemoryConfig, TraceRecordWitnessTable,
    },
    permutation::{PermutationCircuit, PermutationProver, ShuffleChip, ShuffleConfig},
};

#[derive(Debug, Clone)]
/// Config for proving the original trace is sored in time
pub struct ChronicallyOrderedConfig<F: Field + PrimeField> {
    time_log_difference: Column<Advice>,
    time_log_difference_inverse: Column<Advice>,
    first_difference_limb: BinaryConfigure<F, 3>,
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> ChronicallyOrderedConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        time_log: [Column<Advice>; 8],
        selector: Column<Fixed>,
        selector_zero: Selector,
    ) {
        let time_log = [meta.advice_column(); 8];
        let time_log_difference = meta.advice_column();
        let time_log_difference_inverse = meta.advice_column();
        let first_difference_limb = BinaryConfigure::<F, 3>::configure(meta, selector);
        let one = Expression::Constant(F::ONE);

        // time[0]=0
        meta.create_gate("the first time log must be zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let mut time = meta.query_advice(time_log[0], Rotation::cur());
            for i in 1..8 {
                time = time * Expression::Constant(F::from(64_u64))
                    + meta.query_advice(time_log[i], Rotation::cur());
            }
            vec![selector * time]
        });
        // time_log_difference must be non-zero
        meta.create_gate("time_log_difference must be non-zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let time_log_difference = meta.query_advice(time_log_difference, Rotation::cur());
            let time_log_difference_inverse =
                meta.query_advice(time_log_difference_inverse, Rotation::cur());
            vec![selector * (time_log_difference * time_log_difference_inverse - one.clone())]
        });
    }
}

/// Config for consistency check circuit
#[derive(Debug, Clone)]
pub struct ConsistencyConfig<F: Field + PrimeField> {
    lexicographic_ordering_config: SortedMemoryConfig<F>,
    permutation_config: ShuffleConfig,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> ConsistencyConfig<F> {
    fn construct(
        lexicographic_ordering_config: SortedMemoryConfig<F>,
        permutation_config: ShuffleConfig,
    ) -> Self {
        Self {
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
        trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        Self {
            lexicographic_ordering_config: SortedMemoryConfig::<F>::configure(
                meta,
                trace_record,
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
        let lexicographic_ordering_circuit = SortedMemoryCircuit {
            sorted_trace_record,
            _marker: PhantomData,
        };
        lexicographic_ordering_circuit
            .synthesize_with_layouter(config.lexicographic_ordering_config, layouter)?;
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
        Self::Config {
            lexicographic_ordering_config: SortedMemoryCircuit::<F>::configure(meta),
            permutation_config: PermutationCircuit::<F>::configure(meta),
            _marker: PhantomData,
        }
    }

    //TODO: Method: synthesize
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
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
        permutation_circuit.synthesize(config.permutation_config, &layouter)?;
        let mut sorted_trace_record = vec![];
        for (_, trace) in self.shuffle.clone() {
            sorted_trace_record.push(SortedTraceRecord::<F>::from(trace));
        }
        let lexicographic_ordering_circuit = SortedMemoryCircuit {
            sorted_trace_record,
            _marker: PhantomData,
        };
        lexicographic_ordering_circuit
            .synthesize(config.lexicographic_ordering_config, &layouter)?;
        Ok(())
    }
}
