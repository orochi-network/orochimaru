use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};

pub struct IVCStep<F: Field + PrimeField> {
    pub(crate) instance: F,
    pub(crate) witness: Vec<F>,
}

#[derive(Clone, Copy, Debug)]
pub struct Table<const N: usize> {
    col: Column<Fixed>,
}

impl<const N: usize> Table<N> {
    /// Construct the lookup Table.
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



[derive(Clone, Copy, Debug)]
/// Config for binary number
pub struct BinaryConfig<F: Field + PrimeField, const N: usize> {
    /// the list of bit representation
    pub bits: [Column<Advice>; N],
    _marker: PhantomData<F>,
}
impl<F: Field + PrimeField, const N: usize> BinaryConfig<F, N> {
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
        BinaryConfig {
            bits,
            _marker: PhantomData,
        }
    }

    /// Map a value to its corresponding binary witness for the config
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

/// Trace record struct for Lexicographic ordering circuit
/// We need every element to be of an array of type F, where each
#[derive(Debug, Clone)]
pub(crate) struct ConvertedTraceRecord<F: Field + PrimeField> {
    pub(crate) address: [F; 32], // 256 bits
    pub(crate) time_log: [F; 8], // 256 bits
    pub(crate) instruction: F,   // 0 or 1
    pub(crate) value: [F; 32],   // 256 bit
}

impl<F: Field + PrimeField> ConvertedTraceRecord<F> {
    /// Get the trace record fields in tuple
    pub fn get_tuple(&self) -> ([F; 32], [F; 8], F, [F; 32]) {
        (self.address, self.time_log, self.instruction, self.value)
    }
}
// convert the original trace record into a converted trace record
// for serving as the witness of the ciruits
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



