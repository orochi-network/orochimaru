extern crate alloc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Fixed, Selector};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use rand::thread_rng;
extern crate std;

use crate::base::{Base, B256};
use crate::machine::{MemoryInstruction, TraceRecord};

use super::{lexicographic_ordering, permutation};
use super::{
    lexicographic_ordering::{
        LookUpTables, SortedMemoryCircuit, SortedMemoryConfig, TraceRecordWitnessTable,
    },
    permutation::{PermutationCircuit, PermutationProver, ShuffleChip, ShuffleConfig},
};

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
pub struct MemoryConsistencyCircuit<F: Field + PrimeField> {
    /// input_trace: Array of trace records before sorting along with its indexes
    input: Vec<(F, TraceRecord<B256, B256, 32, 32>)>,
    /// shuffle_trace: Array after permutations
    shuffle: Vec<(F, TraceRecord<B256, B256, 32, 32>)>,
}

impl<F: Field + PrimeField> Circuit<F> for MemoryConsistencyCircuit<F> {
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
        Error
    }
}
