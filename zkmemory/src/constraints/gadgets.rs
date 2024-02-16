extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

/// Lookup table for max n bits range check
#[derive(Clone, Copy, Debug)]
pub struct UTable<const N_BITS: usize> {
    col: Column<Fixed>,
}

impl<const N_BITS: usize> UTable<N_BITS> {
    /// Construct the UTable.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            col: meta.fixed_column(),
        }
    }

    /// Load the `UTable` for range check
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "loading column",
            |mut region| {
                for i in 0..(1 << N_BITS) {
                    region.assign_fixed(
                        || "assigning values to column",
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
    pub fn table_exprs<F: Field>(&self, meta: &mut VirtualCells<'_, F>) -> Vec<Expression<F>> {
        vec![meta.query_fixed(self.col, Rotation::cur())]
    }
}
