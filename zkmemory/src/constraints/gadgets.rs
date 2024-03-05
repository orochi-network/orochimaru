extern crate alloc;
extern crate std;

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

/// Lookup table for max n bits range check
#[derive(Clone, Copy, Debug)]
pub struct UTable<const N: usize> {
    col: Column<Fixed>,
}

impl<const N: usize> UTable<N> {
    /// Construct the UTable.
    pub fn construct<F: Field + PrimeField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            col: meta.fixed_column(),
        }
    }

    /// Load the `UTable` for range check
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
                .map(|(exp, table_expr)| (exp, table_expr))
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
