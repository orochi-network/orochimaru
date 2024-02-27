extern crate alloc;
use alloc::vec::Vec;
use alloc::{format, vec};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Value},
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
    pub fn load<F: PrimeField>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || format!("assign u{} fixed column", 8),
            |mut region| {
                for i in 0..N {
                    region.assign_fixed(
                        || format!("assign {} in fixed column of size {}", i, N),
                        self.col,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
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
