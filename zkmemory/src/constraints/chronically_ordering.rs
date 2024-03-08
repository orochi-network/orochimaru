extern crate alloc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::circuit::{Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Fixed, Selector};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Circuit, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};
use rand::thread_rng;
use std::println;
extern crate std;

use crate::constraints::gadgets::Queries;

use super::common::CircuitExtension;
use super::gadgets::Table;
use super::gadgets::{ConvertedTraceRecord, GreaterThanConfigure};
use super::gadgets::{LookUpTables, TraceRecordWitnessTable};
#[derive(Clone, Copy, Debug)]
/// fuck
pub(crate) struct OriginalMemoryConfig<F: Field + PrimeField> {
    pub(crate) trace_record: TraceRecordWitnessTable<F>,
    pub(crate) selector: Column<Fixed>,
    pub(crate) selector_zero: Selector,
    pub(crate) greater_than: GreaterThanConfigure<F, 3>,
    pub(crate) lookup_tables: LookUpTables,
}
impl<F: Field + PrimeField> OriginalMemoryConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
        let greater_than = GreaterThanConfigure::<F, 3>::configure(
            meta,
            trace_record,
            alpha_power,
            lookup_tables,
            selector,
            false,
        );
        meta.create_gate("first accessed memory is at time 0", |meta| {
            let selector_zero = meta.query_selector(selector_zero);
            let time_log = Queries::new(meta, trace_record, Rotation::cur()).time_log;
            let mut time = time_log[0].clone();
            for i in 1..8 {
                time = time * Expression::Constant(F::from(64_u64)) + time_log[i].clone();
            }
            vec![selector_zero * time]
        });
        OriginalMemoryConfig {
            trace_record,
            selector,
            selector_zero,
            greater_than,
            lookup_tables,
        }
    }
}

/// Circuit for sorted trace record
#[derive(Default)]
pub(crate) struct OriginalMemoryCircuit<F: PrimeField> {
    pub(crate) original_trace_record: Vec<ConvertedTraceRecord<F>>,
    pub(crate) _marker: PhantomData<F>,
}

/// Implement the CircuitExtension trait for the SortedMemoryCircuit
impl<F: Field + PrimeField> CircuitExtension<F> for OriginalMemoryCircuit<F> {
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "lexicographic_ordering",
            |mut region| {
                for i in 0..self.original_trace_record.len() {
                    self.original_memory_assign(&mut region, config, i)?;
                }
                config.lookup_tables.size40_table.load(&mut region)?;
                config.lookup_tables.size64_table.load(&mut region)?;
                config.lookup_tables.size2_table.load(&mut region)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: Field + PrimeField> Circuit<F> for OriginalMemoryCircuit<F> {
    type Config = OriginalMemoryConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    // configure the circuit
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

        OriginalMemoryConfig::configure(meta, trace_record, lookup_tables, alpha_power)
    }

    // assign the witness values to the entire witness table and their constraints
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.synthesize_with_layouter(config, &mut layouter)
    }
}

impl<F: Field + PrimeField> OriginalMemoryCircuit<F> {
    // assign the witness values to the offset-th row of the witness table
    fn original_memory_assign(
        &self,
        region: &mut Region<'_, F>,
        config: OriginalMemoryConfig<F>,
        offset: usize,
    ) -> Result<(), Error> {
        // handle the case offset=0
        if offset == 0 {
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.original_trace_record[offset].get_tuple();

            config.selector_zero.enable(region, offset)?;
            // assign the address witness
            for (i, j) in cur_address.iter().zip(config.trace_record.address) {
                region.assign_advice(
                    || format!("address{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }
            // assign the time_log witness
            for (i, j) in cur_time_log.iter().zip(config.trace_record.time_log) {
                region.assign_advice(
                    || format!("time_log{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }
            // assign the instruction witness
            region.assign_advice(
                || format!("instruction{}", offset),
                config.trace_record.instruction,
                offset,
                || Value::known(cur_instruction),
            )?;
            // assign the value witness
            for (i, j) in cur_value.iter().zip(config.trace_record.value) {
                region.assign_advice(
                    || format!("value{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }
        }
        // handle the case offset >= 1
        else {
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.original_trace_record[offset].get_tuple();
            let (_prev_address, prev_time_log, _prev_instruction, _prev_value) =
                self.original_trace_record[offset - 1].get_tuple();
            let cur_be_limbs = self.time_log_to_be_limbs(cur_time_log);
            let prev_be_limbs = self.time_log_to_be_limbs(prev_time_log);
            let mut limb_vector = vec![0_u8];
            for i in 1..8 {
                limb_vector.push(i);
            }
            // find the minimal index such that cur is not equal to prev
            let find_result = limb_vector
                .iter()
                .zip(&cur_be_limbs)
                .zip(&prev_be_limbs)
                .find(|((_, a), b)| a != b);
            let zero = F::ZERO;
            let ((index, cur_limb), prev_limb) = if cfg!(test) {
                find_result.unwrap_or(((&8, &zero), &zero))
            } else {
                find_result.expect("two trace records cannot be the same")
            };
            let difference = *cur_limb - *prev_limb;

            // assign the selector to be one at the current row
            region.assign_fixed(
                || "selector",
                config.selector,
                offset,
                || Value::known(F::ONE),
            )?;

            // assign the address witness
            for (i, j) in cur_address.iter().zip(config.trace_record.address) {
                region.assign_advice(
                    || format!("address{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }

            // assign the time_log witness
            for (i, j) in cur_time_log.iter().zip(config.trace_record.time_log) {
                region.assign_advice(
                    || format!("time_log{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }

            // assign the instruction witness
            region.assign_advice(
                || format!("instruction{}", offset),
                config.trace_record.instruction,
                offset,
                || Value::known(cur_instruction),
            )?;

            // assign the value witness
            for (i, j) in cur_value.iter().zip(config.trace_record.value) {
                region.assign_advice(
                    || format!("value{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }

            // assign the difference of time witness
            region.assign_advice(
                || format!("difference of time_log{}", offset),
                config.greater_than.difference,
                offset,
                || Value::known(difference),
            )?;

            // assign the inverse of the time difference witness
            region.assign_advice(
                || format!("time_log difference_inverse{}", offset),
                config.greater_than.difference_inverse,
                offset,
                || Value::known(difference.invert().expect("cannot find inverse")),
            )?;

            // assign the first_difference_limb witness
            config
                .greater_than
                .first_difference_limb
                .assign(region, offset, *index)?;
        }
        Ok(())
    }

    fn time_log_to_be_limbs(&self, time_log: [F; 8]) -> Vec<F> {
        let mut be_bytes = vec![];
        be_bytes.extend_from_slice(&time_log);
        be_bytes
    }
}

mod test {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    #[test]
    fn test_ok_one_trace() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };
        let trace = vec![trace0];
        let circuit = OriginalMemoryCircuit {
            original_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_wrong_starting_time() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };
        let trace = vec![trace0];
        let circuit = OriginalMemoryCircuit {
            original_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }
}
