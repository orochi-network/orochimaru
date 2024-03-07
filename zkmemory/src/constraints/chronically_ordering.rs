extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::{iter::once, marker::PhantomData};
use ff::{Field, PrimeField};
use halo2_proofs::circuit::SimpleFloorPlanner;
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

use super::common::CircuitExtension;
use super::gadgets::{equal_value, BinaryConfigure, Table};
use super::lexicographic_ordering::SortedTraceRecord;
use super::{
    lexicographic_ordering::{
        LookUpTables, SortedMemoryCircuit, SortedMemoryConfig, TraceRecordWitnessTable,
    },
    permutation::{PermutationCircuit, ShuffleChip, ShuffleConfig},
};
#[derive(Debug, Clone)]
/// Config for proving the original trace is sored in time
pub(crate) struct ChronicallyOrderedConfig<F: Field + PrimeField> {
    pub(crate) time_log: Vec<[Expression<F>; 8]>,
    pub(crate) time_log_difference: Column<Advice>,
    pub(crate) time_log_difference_inverse: Column<Advice>,
    pub(crate) first_difference_limb: BinaryConfigure<F, 3>,
    pub(crate) selector: Column<Fixed>,
    pub(crate) selector_zero: Selector,
    pub(crate) _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> ChronicallyOrderedConfig<F> {
    ///
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        trace_record: TraceRecordWitnessTable<F>,
        alpha_power: Vec<Expression<F>>,
        lookup_tables: LookUpTables,
    ) -> Self {
        let time_log = [meta.advice_column(); 8];
        let time_log_difference = meta.advice_column();
        let time_log_difference_inverse = meta.advice_column();
        let selector = meta.fixed_column();
        let first_difference_limb = BinaryConfigure::<F, 3>::configure(meta, selector);
        let one = Expression::Constant(F::ONE);
        let selector_zero = meta.selector();
        let mut limb_vector = vec![0_u8];
        for i in 1..8 {
            limb_vector.push(i);
        }

        // time[0]=0
        meta.create_gate("the first time log must be zero", |meta| {
            let selector_zero = meta.query_selector(selector_zero);
            let time_log = [0..8].;
            let mut time = time_log[0].clone();
            for i in 1..8 {
                time = time * Expression::Constant(F::from(64_u64)) + time_log[i].clone();
            }
            vec![selector_zero * time]
        });
        // time_log_difference must be non-zero
        meta.create_gate("time_log_difference must be non-zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let time_log_difference = meta.query_advice(time_log_difference, Rotation::cur());
            let time_log_difference_inverse =
                meta.query_advice(time_log_difference_inverse, Rotation::cur());
            vec![selector * (time_log_difference * time_log_difference_inverse - one.clone())]
        });
        // all limbs before first_difference_limb are all zero
          meta.create_gate(
            "all limbs before first_difference_limb are all zero",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let first_difference_limb = first_difference_limb
                    .bits
                    .map(|tmp| meta.query_advice(tmp, Rotation::cur()));
                let mut result = vec![];
                let mut partial_sum = Expression::Constant(F::ZERO);
                let alpha_power = once(Expression::Constant(F::ONE)).chain(alpha_power);
                for ((cur_limb, prev_limb), power_of_randomness) in
                    cur.iter().zip(&prev).zip(alpha_power)
                {
                    result.push(partial_sum.clone());
                    partial_sum =
                        partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
                }
                let mut constraints = vec![];
                for (i, rlc_expression) in limb_vector.iter().zip(result) {
                    constraints.push(
                        selector.clone()
                            * rlc_expression
                            * equal_value(first_difference_limb.clone(), *i),
                    );
                }
                constraints
            },
        );

        // time_log_difference equal to the difference of time log at first_limb_index
        meta.create_gate(
            "time_log_difference equal to the difference of time log at first_limb_index",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
               let cur=
                let time_log_difference = meta.query_advice(time_log_difference, Rotation::cur());
                let first_difference_limb = first_difference_limb
                    .bits
                    .map(|tmp| meta.query_advice(tmp, Rotation::cur()));
                let mut constraints = vec![];
                for ((i, cur_limb), prev_limb) in limb_vector.iter().zip(&cur).zip(&prev) {
                    constraints.push(
                        selector.clone()
                            * equal_value(first_difference_limb.clone(), *i)
                            * (time_log_difference.clone() - cur_limb.clone() + prev_limb.clone()),
                    )
                }
                constraints
            },
        );
        // lookup gate for difference. It must be in [0..64]
        lookup_tables
            .size64_table
            .range_check(meta, "difference fits in 0..64", |meta| {
                meta.query_advice(time_log_difference, Rotation::cur())
            });

        ChronicallyOrderedConfig {
            time_log,
            time_log_difference,
            time_log_difference_inverse,
            first_difference_limb,
            selector,
            selector_zero,
            _marker: PhantomData,
        }
    }
}

pub(crate) struct ChronicallyOrderedCircuit<F: Field + PrimeField> {
    time_log: Vec<[F; 8]>,
}

impl<F: Field + PrimeField> Circuit<F> for ChronicallyOrderedCircuit<F> {
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rng = thread_rng();

        // the elements of the trace record
        let trace_record = TraceRecordWitnessTable::<F>::new(meta);

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

        SortedMemoryConfig::configure(meta, trace_record, lookup_tables, alpha_power)
    }
}
