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