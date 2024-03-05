extern crate alloc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::{iter::once, marker::PhantomData};
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

use super::gadgets::*;

/// The witness table consisting of the elements of the trace records
#[derive(Clone, Copy, Debug)]
pub struct TraceRecordWitnessTable<F: Field + PrimeField> {
    address: [Column<Advice>; 32],
    time_log: [Column<Advice>; 8],
    instruction: Column<Advice>,
    value: [Column<Advice>; 32],
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> TraceRecordWitnessTable<F> {
    fn new(meta: &mut ConstraintSystem<F>) -> Self {
        TraceRecordWitnessTable {
            address: [meta.advice_column(); 32],
            time_log: [meta.advice_column(); 8],
            instruction: meta.advice_column(),
            value: [meta.advice_column(); 32],
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// check the lexicographic ordering of address||time
pub struct GreaterThanConfigure<F: Field + PrimeField> {
    difference: Column<Advice>,
    difference_inverse: Column<Advice>,
    first_difference_limb: BinaryConfigure<F, 6>,
}

impl<F: Field + PrimeField> GreaterThanConfigure<F> {
    /// Add the constraints for lexicographic ordering
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        trace_record: TraceRecordWitnessTable<F>,
        alpha_power: Vec<Expression<F>>,
        lookup_tables: LookUpTables,
        selector: Column<Fixed>,
    ) -> Self {
        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let first_difference_limb = BinaryConfigure::<F, 6>::configure(meta, selector);
        let one = Expression::Constant(F::ONE);
        let mut limb_vector = vec![0_u8];
        for i in 1..40 {
            limb_vector.push(i);
        }

        // inversion gate for difference
        meta.create_gate("difference is non-zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let difference = meta.query_advice(difference, Rotation::cur());
            let difference_inverse = meta.query_advice(difference_inverse, Rotation::cur());
            vec![selector * (difference * difference_inverse - one.clone())]
        });

        // limbs before first differences are zero
        meta.create_gate("limbs before first differences are zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let first_difference_limb = first_difference_limb
                .bits
                .map(|tmp| meta.query_advice(tmp, Rotation::cur()));
            let cur = Queries::new(meta, trace_record, Rotation::cur());
            let prev = Queries::new(meta, trace_record, Rotation::prev());
            let rlc = rlc_limb_differences(cur, prev, alpha_power.clone());
            let mut constraints = vec![];
            for (i, rlc_expression) in limb_vector.iter().zip(rlc) {
                constraints.push(
                    selector.clone()
                        * rlc_expression
                        * equal_value(first_difference_limb.clone(), *i),
                );
            }
            constraints
        });

        // difference equals difference of limbs at index
        meta.create_gate("difference equals difference of limbs at index", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, trace_record, Rotation::cur());
            let prev = Queries::new(meta, trace_record, Rotation::prev());
            let difference = meta.query_advice(difference, Rotation::cur());
            let first_difference_limb = first_difference_limb
                .bits
                .map(|tmp| meta.query_advice(tmp, Rotation::cur()));
            let mut constraints = vec![];
            for ((i, cur_limb), prev_limb) in limb_vector
                .iter()
                .zip(&cur.be_limbs())
                .zip(&prev.be_limbs())
            {
                constraints.push(
                    selector.clone()
                        * equal_value(first_difference_limb.clone(), *i)
                        * (difference.clone() - cur_limb.clone() + prev_limb.clone()),
                )
            }
            constraints
        });

        // first_difference_limb is in [0..39]
        lookup_tables.size40_table.range_check(
            meta,
            "first_difference_limb must be in 0..39",
            |meta| {
                let first_difference_limb = first_difference_limb
                    .bits
                    .map(|tmp| meta.query_advice(tmp, Rotation::cur()));
                let val = first_difference_limb
                    .iter()
                    .fold(Expression::Constant(F::from(0_u64)), |result, bit| {
                        bit.clone() + result * Expression::Constant(F::from(2_u64))
                    });
                val
            },
        );

        // lookup gate for difference. It must be in [0..64]
        lookup_tables
            .size64_table
            .range_check(meta, "difference fits in 0..64", |meta| {
                meta.query_advice(difference, Rotation::cur())
            });

        GreaterThanConfigure {
            difference,
            difference_inverse,
            first_difference_limb,
        }
    }
}

/// The lookup tables
#[derive(Clone, Copy, Debug)]
pub struct LookUpTables {
    size64_table: Table<64>,
    size40_table: Table<40>,
    size2_table: Table<2>,
}

#[derive(Clone, Copy, Debug)]
/// define the columns for the constraint
pub struct SortedMemoryConfig<F: Field + PrimeField> {
    //  the fields of an execution trace
    trace_record: TraceRecordWitnessTable<F>,
    // the difference between the current and the previous address
    addr_cur_prev: IsZeroConfigure<F>,
    // the config for checking the current address||time_log is bigger
    // than the previous one
    greater_than: GreaterThanConfigure<F>,
    // the selectors
    selector: Column<Fixed>,
    selector_zero: Selector,
    // the lookup table
    lookup_tables: LookUpTables,
    // just the phantom data
    _marker: PhantomData<F>,
}

// implement the configure method for selecting gates
// we have the gates for checking inverse, lookup and checking that
// all values before first_difference_limb are equal to zero
impl<F: Field + PrimeField> SortedMemoryConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        let one = Expression::Constant(F::ONE);

        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
        let addr_cur_prev = IsZeroConfigure::<F>::configure(meta, selector);

        // addr[i+1]>addr[i] OR addr[i+1]=addr[i] and time[i+1]>time[i]
        let greater_than = GreaterThanConfigure::<F>::configure(
            meta,
            trace_record,
            alpha_power,
            lookup_tables,
            selector,
        );

        let mut limb_vector = vec![0_u8];
        for i in 1..40 {
            limb_vector.push(i);
        }

        // instruction[0]=1
        meta.create_gate("instruction of the first access must be write", |meta| {
            let cur = Queries::new(meta, trace_record, Rotation::cur());
            let selector_zero = meta.query_selector(selector_zero);
            vec![selector_zero * (cur.instruction - one.clone())]
        });

        // (addr[i+1]-addr[i])*(instruction[i+1]-1)*(val[i+1]-val[i])=0
        meta.create_gate("if the current trace is read, then its value must be equal to the previous trace value", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta,trace_record,Rotation::cur());
            let prev = Queries::new(meta,trace_record,Rotation::prev());
            let val=meta.query_advice(addr_cur_prev.val, Rotation::cur());
            let temp=meta.query_advice(addr_cur_prev.temp, Rotation::cur());
            let val_diff=limbs_to_expression(cur.value)-limbs_to_expression(prev.value);
          let tmp=one.clone()-val.clone()*temp;
          let tmp2=limbs_to_expression(cur.address)-limbs_to_expression(prev.address)-val.clone();
            vec![selector.clone() * (cur.instruction - one.clone()) * val_diff*tmp, selector.clone()*tmp2]
        });

        // (addr[i+1]-addr[i])*(instruction[i+1]-1)=0
        meta.create_gate(
            "the first time an address is accessed, it instruction must be write",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cur = Queries::new(meta, trace_record, Rotation::cur());
                let prev = Queries::new(meta, trace_record, Rotation::prev());
                let addr_diff =
                    limbs_to_expression(cur.address) - limbs_to_expression(prev.address);
                vec![selector * (cur.instruction - one.clone()) * addr_diff.clone()]
            },
        );

        // instruction[i]=1 for all i
        lookup_tables
            .size2_table
            .range_check(meta, "instruction must be in 0..1", |meta| {
                meta.query_advice(trace_record.instruction, Rotation::cur())
            });

        // each limb of address and value must be in [0..64]
        for (addr, val) in trace_record.address.iter().zip(&trace_record.value) {
            lookup_tables
                .size64_table
                .range_check(meta, "limb of address fits in 0..64", |meta| {
                    meta.query_advice(*addr, Rotation::cur())
                });
            lookup_tables
                .size64_table
                .range_check(meta, "limb of value fits in 0..64", |meta| {
                    meta.query_advice(*val, Rotation::cur())
                });
        }

        // each limb of time_log must be in [0..64]
        for i in trace_record.time_log {
            lookup_tables.size64_table.range_check(
                meta,
                "limb of time log fits in 0..64",
                |meta| meta.query_advice(i, Rotation::cur()),
            );
        }

        // return the config after assigning the gates
        SortedMemoryConfig {
            trace_record,
            addr_cur_prev,
            greater_than,
            selector,
            selector_zero,
            lookup_tables,
            _marker: PhantomData,
        }
    }
}

fn limbs_to_expression<F: Field + PrimeField>(limb: [Expression<F>; 32]) -> Expression<F> {
    let mut sum = Expression::Constant(F::ZERO);
    let mut tmp = Expression::Constant(F::from(256_u64));
    for i in 0..32 {
        sum = sum + tmp.clone() * limb[31 - i].clone();
        tmp = tmp * Expression::Constant(F::from(256_u64));
    }
    sum
}

// Returns a vector of length 32 with the rlc of the limb differences between
// from 0 to i-l. 0 for i=0,
fn rlc_limb_differences<F: Field + PrimeField>(
    cur: Queries<F>,
    prev: Queries<F>,
    alpha_power: Vec<Expression<F>>,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = Expression::Constant(F::ZERO);
    let alpha_power = once(Expression::Constant(F::ONE)).chain(alpha_power);
    for ((cur_limb, prev_limb), power_of_randomness) in
        cur.be_limbs().iter().zip(&prev.be_limbs()).zip(alpha_power)
    {
        result.push(partial_sum.clone());
        partial_sum = partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
    }
    result
}

// Query the element of a trace record at a specific position
struct Queries<F: Field + PrimeField> {
    address: [Expression<F>; 32], //64 bits
    time_log: [Expression<F>; 8], //64 bits
    instruction: Expression<F>,   // 0 or 1
    value: [Expression<F>; 32],   //64 bit
}

impl<F: Field + PrimeField> Queries<F> {
    // converts the attributes of a trace record to type Expression<F>
    fn new(
        meta: &mut VirtualCells<'_, F>,
        trace_record: TraceRecordWitnessTable<F>,
        rotation: Rotation,
    ) -> Self {
        let mut query_advice = |column| meta.query_advice(column, rotation);
        Self {
            address: trace_record.address.map(&mut query_advice),
            time_log: trace_record.time_log.map(&mut query_advice),
            instruction: query_advice(trace_record.instruction),
            value: trace_record.value.map(&mut query_advice),
        }
    }

    // stack address and time_log into a single array for comparison
    fn be_limbs(&self) -> Vec<Expression<F>> {
        self.address
            .iter()
            .rev()
            .chain(self.time_log.iter().rev())
            .cloned()
            .collect()
    }
}

struct SortedTraceRecord<F: Field + PrimeField> {
    address: [F; 32], //256 bits
    time_log: [F; 8], //256 bits
    instruction: F,   // 0 or 1
    value: [F; 32],   //256 bit
}

impl<F: Field + PrimeField> SortedTraceRecord<F> {
    fn get_tuple(&self) -> ([F; 32], [F; 8], F, [F; 32]) {
        (self.address, self.time_log, self.instruction, self.value)
    }
}

impl<F: Field + PrimeField> From<TraceRecord<B256, B256, 32, 32>> for SortedTraceRecord<F> {
    fn from(value: TraceRecord<B256, B256, 32, 32>) -> Self {
        Self {
            address: value
                .get_tuple()
                .3
                .fixed_be_bytes()
                .into_iter()
                .map(|b| F::from(u64::from(b)))
                .collect::<Vec<F>>()
                .try_into()
                .expect("Cannot convert address to [F; 32]"),
            time_log: value
                .get_tuple()
                .0
                .to_be_bytes()
                .into_iter()
                .map(|b| F::from(u64::from(b)))
                .collect::<Vec<F>>()
                .try_into()
                .expect("Cannot convert time_log to [F; 8]"),
            instruction: match value.get_tuple().2 {
                MemoryInstruction::Write => F::ONE,
                MemoryInstruction::Read => F::ZERO,
            },
            value: value
                .get_tuple()
                .4
                .fixed_be_bytes()
                .into_iter()
                .map(|b| F::from(u64::from(b)))
                .collect::<Vec<F>>()
                .try_into()
                .expect("Cannot convert value to [F; 32]"),
        }
    }
}

/// Circuit for sorted trace record
#[derive(Default)]
pub struct SortedMemoryCircuit<F: PrimeField> {
    sorted_trace_record: Vec<SortedTraceRecord<F>>,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> Circuit<F> for SortedMemoryCircuit<F> {
    type Config = SortedMemoryConfig<F>;
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

        SortedMemoryConfig::configure(meta, trace_record, lookup_tables, alpha_power)
    }

    // assign the witness values to the entire witness table and their constraints
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "lexicographic_ordering",
            |mut region| {
                for i in 0..self.sorted_trace_record.len() {
                    self.assign(&mut region, config, i)?;
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

impl<F: Field + PrimeField> SortedMemoryCircuit<F> {
    // assign the witness values to the offset-th row of the witness table
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        config: SortedMemoryConfig<F>,
        offset: usize,
    ) -> Result<(), Error> {
        // handle the case offset=0
        if offset == 0 {
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.sorted_trace_record[offset].get_tuple();

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
            let rng = thread_rng();
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.sorted_trace_record[offset].get_tuple();
            let (prev_address, prev_time_log, _prev_instruction, _prev_value) =
                self.sorted_trace_record[offset - 1].get_tuple();
            let cur_be_limbs = self.trace_to_be_limbs(cur_time_log, cur_address);
            let prev_be_limbs = self.trace_to_be_limbs(prev_time_log, prev_address);
            let mut limb_vector = vec![0_u8];
            for i in 1..40 {
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
                find_result.unwrap_or(((&40, &zero), &zero))
            } else {
                find_result.expect("two trace records cannot be the same")
            };
            let difference = *cur_limb - *prev_limb;

            let address_diff =
                self.address_limb_to_field(cur_address) - self.address_limb_to_field(prev_address);
            let temp;
            let temp_inv;
            if address_diff == F::ZERO {
                temp = F::random(rng);
                temp_inv = temp.invert().expect("cannot find inverse");
            } else {
                temp = address_diff.invert().expect("cannot find inverse");
                temp_inv = address_diff;
            }

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

            // assign the address difference witness
            region.assign_advice(
                || format!("difference of address{}", offset),
                config.addr_cur_prev.val,
                offset,
                || Value::known(address_diff),
            )?;

            // assign the inverse of address difference witness
            region.assign_advice(
                || format!("inverse difference of address{}", offset),
                config.addr_cur_prev.temp,
                offset,
                || Value::known(temp),
            )?;

            // assign the inverse of inverse of address difference witness
            region.assign_advice(
                || format!("inverse of inverse of address{}", offset),
                config.addr_cur_prev.temp_inv,
                offset,
                || Value::known(temp_inv),
            )?;

            // assign the difference of address||time witness
            region.assign_advice(
                || format!("difference of address||time_log{}", offset),
                config.greater_than.difference,
                offset,
                || Value::known(difference),
            )?;

            // assign the inverse of the address||time difference witness
            region.assign_advice(
                || format!("address||time_log difference_inverse{}", offset),
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

    fn trace_to_be_limbs(&self, time_log: [F; 8], address: [F; 32]) -> Vec<F> {
        let mut be_bytes = vec![];
        be_bytes.extend_from_slice(&address);
        be_bytes.extend_from_slice(&time_log);
        be_bytes
    }

    fn address_limb_to_field(&self, address: [F; 32]) -> F {
        let mut sum = F::ZERO;
        let mut tmp = F::from(256_u64);
        for i in 0..32 {
            sum += tmp * address[31 - i];
            tmp *= F::from(256_u64);
        }
        sum
    }
}

#[cfg(test)]
mod test {
    // use core::marker::PhantomData;

    // use crate::constraints::lexicographic_ordering::SortedMemoryCircuit;

    // use super::SortedTraceRecord;
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    #[test]
    fn test_ok_one_trace() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };
        let trace = vec![trace0];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_error_invalid_instruction() {
        // first instruction is supposed to be write
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        let trace = vec![trace0];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_address() {
        // each limb of address is supposed to be in [0..63]
        let trace0 = SortedTraceRecord {
            address: [Fp::from(64); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        let trace = vec![trace0];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_time_log() {
        // each limb of address is supposed to be in [0..63]
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(64); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        let trace = vec![trace0];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_value() {
        // each limb of address is supposed to be in [0..63]
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(64); 32],
        };
        let trace = vec![trace0];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_ok_two_trace() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace = vec![trace0, trace1];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_address_order() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(1); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace = vec![trace0, trace1];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn wrong_time_log_order() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace = vec![trace0, trace1];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn invalid_read() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(50); 32],
        };

        let trace = vec![trace0, trace1];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn non_first_write_access_for_two_traces() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(1); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(50); 32],
        };

        let trace = vec![trace0, trace1];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_ok_three_trace() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace2 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(2); 8],
            instruction: Fp::from(1),
            value: [Fp::from(50); 32],
        };

        let trace = vec![trace0, trace1, trace2];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn invalid_read2() {
        let trace0 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(2); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace2 = SortedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(3); 8],
            instruction: Fp::from(0),
            value: [Fp::from(50); 32],
        };

        let trace = vec![trace0, trace1, trace2];
        let circuit = SortedMemoryCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_ne!(prover.verify(), Ok(()));
    }
}
