extern crate alloc;
extern crate std;

use core::iter::once;
use core::marker::PhantomData;

use alloc::vec::Vec;
use alloc::{format, vec};
use ff::{Field, PrimeField};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Advice;
use halo2_proofs::{
    circuit::Value,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;

use crate::base::{Base, B256};
use crate::machine::{MemoryInstruction, TraceRecord};

/// Lookup table for max n bits range check
#[derive(Clone, Copy, Debug)]
pub struct Table<const N: usize> {
    col: Column<Fixed>,
}

impl<const N: usize> Table<N> {
    /// Construct the Table.
    pub fn construct<F: Field + PrimeField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            col: meta.fixed_column(),
        }
    }

    /// Load the `Table` for range check
    pub fn load<F: Field + PrimeField>(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        for i in 0..N {
            region.assign_fixed(
                || format!("assign {} in fixed column of size {}", i, N),
                self.col,
                i,
                || Value::known(F::from(i as u64)),
            )?;
        }
        Ok(())
    }

    /// Return the list of expressions used to define the table
    pub fn table_exprs<F: PrimeField>(&self, meta: &mut VirtualCells<'_, F>) -> Vec<Expression<F>> {
        vec![meta.query_fixed(self.col, Rotation::cur())]
    }

    /// Perform the range check
    pub fn range_check<F: Field + PrimeField>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![exp]
                .into_iter()
                .zip_eq(self.table_exprs(meta))
                .collect()
        });
    }
}

/// check if a value val is zero or not
#[derive(Clone, Copy, Debug)]
pub struct IsZeroConfigure<F: Field + PrimeField> {
    /// the value
    pub val: Column<Advice>,
    /// the inverse of value. It is any non-zero value if val=0
    pub temp: Column<Advice>,
    /// the inverse of temp.
    pub temp_inv: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> IsZeroConfigure<F> {
    /// Create the gates for checking inversion
    pub fn configure(meta: &mut ConstraintSystem<F>, selector: Column<Fixed>) -> Self {
        let val = meta.advice_column();
        let temp = meta.advice_column();
        let temp_inv = meta.advice_column();
        let one = Expression::Constant(F::ONE);

        // temp*temp_inv is equal to 1
        meta.create_gate("temp*temp_inv is equal to 1", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let temp = meta.query_advice(temp, Rotation::cur());
            let temp_inv = meta.query_advice(temp_inv, Rotation::cur());
            vec![selector * (temp * temp_inv - one.clone())]
        });

        // if val is non-zero, then temp is the inversion of val
        meta.create_gate("val*temp is equal to 0 or 1", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let val = meta.query_advice(val, Rotation::cur());
            let temp = meta.query_advice(temp, Rotation::cur());
            vec![selector * (temp.clone() * val.clone() * (one.clone() - temp * val))]
        });

        IsZeroConfigure {
            val,
            temp,
            temp_inv,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Config for binary number
pub struct BinaryConfigure<F: Field + PrimeField, const N: usize> {
    /// the list of bit representation
    pub bits: [Column<Advice>; N],
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField, const N: usize> BinaryConfigure<F, N> {
    /// Requires that each bit is zero or one
    pub fn configure(meta: &mut ConstraintSystem<F>, selector: Column<Fixed>) -> Self {
        let bits = [0; N].map(|_| meta.advice_column());
        let one = Expression::Constant(F::ONE);
        bits.map(|bit| {
            meta.create_gate("bit column is 0 or 1", |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let bit = meta.query_advice(bit, Rotation::cur());
                vec![selector * bit.clone() * (one.clone() - bit)]
            })
        });
        BinaryConfigure {
            bits,
            _marker: PhantomData,
        }
    }

    /// map a value to its corresponding binary witness for the config
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: u8,
    ) -> Result<(), Error> {
        for (&bit, &column) in as_bits::<N>(value).iter().zip(&self.bits) {
            region.assign_advice(
                || format!("binary number {:?}", column),
                column,
                offset,
                || Value::known(F::from(bit as u64)),
            )?;
        }
        Ok(())
    }
}

// convert a value into an binary array of size N
fn as_bits<const N: usize>(value: u8) -> [u8; N] {
    let mut value = value;
    let mut bits = [0; N];
    for i in 0..N {
        bits[N - 1 - i] = value % 2;
        value /= 2;
    }
    bits
}

/// return 1 if lhs=rhs as bits and 0 otherwise
pub fn equal_value<F: Field + PrimeField, const N: usize>(
    lhs: [Expression<F>; N],
    rhs: u8,
) -> Expression<F> {
    let mut acc = Expression::Constant(F::ONE);
    let one = Expression::Constant(F::ONE);
    let rhs = as_bits::<N>(rhs);
    for (r, l) in rhs.iter().zip(lhs) {
        let rr = Expression::Constant(F::from(*r as u64));
        acc = acc * (one.clone() - (l.clone() - rr.clone()) * (l - rr));
    }
    acc
}

/// The witness table consisting of the elements of the trace records
#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceRecordWitnessTable<F: Field + PrimeField> {
    pub(crate) address: [Column<Advice>; 32],
    pub(crate) time_log: [Column<Advice>; 8],
    pub(crate) instruction: Column<Advice>,
    pub(crate) value: [Column<Advice>; 32],
    pub(crate) _marker: PhantomData<F>,
}
impl<F: Field + PrimeField> TraceRecordWitnessTable<F> {
    /// New Witness table
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        TraceRecordWitnessTable {
            address: [0; 32].map(|_| meta.advice_column()),
            time_log: [0; 8].map(|_| meta.advice_column()),
            instruction: meta.advice_column(),
            value: [0; 32].map(|_| meta.advice_column()),
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// check the lexicographic ordering of time or address||time
pub(crate) struct GreaterThanConfigure<F: Field + PrimeField, const N: usize> {
    pub(crate) difference: Column<Advice>,
    pub(crate) difference_inverse: Column<Advice>,
    pub(crate) first_difference_limb: BinaryConfigure<F, N>,
}

impl<F: Field + PrimeField, const N: usize> GreaterThanConfigure<F, N> {
    /// Add the constraints for lexicographic ordering
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        trace_record: TraceRecordWitnessTable<F>,
        alpha_power: Vec<Expression<F>>,
        lookup_tables: LookUpTables,
        selector: Column<Fixed>,
        address_included: bool,
    ) -> Self {
        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let first_difference_limb = BinaryConfigure::<F, N>::configure(meta, selector);
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
            let rlc = rlc_limb_differences(cur, prev, alpha_power.clone(), address_included);
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
                .zip(&cur.be_limbs(address_included))
                .zip(&prev.be_limbs(address_included))
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
        if address_included {
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
        }
        // lookup gate for difference. It must be in [0..64]
        lookup_tables
            .size256_table
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

// Returns a vector of length 32 with the rlc of the limb differences between
// from 0 to i-l. 0 for i=0,
fn rlc_limb_differences<F: Field + PrimeField>(
    cur: Queries<F>,
    prev: Queries<F>,
    alpha_power: Vec<Expression<F>>,
    address_included: bool,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = Expression::Constant(F::ZERO);
    let alpha_power = once(Expression::Constant(F::ONE)).chain(alpha_power);
    for ((cur_limb, prev_limb), power_of_randomness) in cur
        .be_limbs(address_included)
        .iter()
        .zip(&prev.be_limbs(address_included))
        .zip(alpha_power)
    {
        result.push(partial_sum.clone());
        partial_sum = partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
    }
    result
}

/// The lookup tables
#[derive(Clone, Copy, Debug)]
pub(crate) struct LookUpTables {
    pub(crate) size256_table: Table<256>,
    pub(crate) size40_table: Table<40>,
    pub(crate) size2_table: Table<2>,
}

/// Query the element of a trace record at a specific position
#[derive(Clone, Debug)]
pub(crate) struct Queries<F: Field + PrimeField> {
    pub(crate) address: [Expression<F>; 32], //64 bits
    pub(crate) time_log: [Expression<F>; 8], //64 bits
    pub(crate) instruction: Expression<F>,   // 0 or 1
    pub(crate) value: [Expression<F>; 32],   //64 bit
}

impl<F: Field + PrimeField> Queries<F> {
    /// converts the attributes of a trace record to type Expression<F>
    pub fn new(
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
    fn be_limbs(&self, address_included: bool) -> Vec<Expression<F>> {
        if !address_included {
            return self.time_log.to_vec();
        }
        let mut result = vec![];
        for i in self.address.iter() {
            result.push(i.clone())
        }
        for i in self.time_log.iter() {
            result.push(i.clone())
        }
        result
    }
}
/// Trace record struct for Lexicographic ordering circuit
#[derive(Debug, Clone)]
pub(crate) struct ConvertedTraceRecord<F: Field + PrimeField> {
    pub(crate) address: [F; 32], //256 bits
    pub(crate) time_log: [F; 8], //256 bits
    pub(crate) instruction: F,   // 0 or 1
    pub(crate) value: [F; 32],   //256 bit
}

impl<F: Field + PrimeField> ConvertedTraceRecord<F> {
    /// Get the trace record fields in tuple
    pub fn get_tuple(&self) -> ([F; 32], [F; 8], F, [F; 32]) {
        (self.address, self.time_log, self.instruction, self.value)
    }
}

impl<F: Field + PrimeField> From<TraceRecord<B256, B256, 32, 32>> for ConvertedTraceRecord<F> {
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
