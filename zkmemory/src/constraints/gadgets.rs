extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use halo2_proofs::{
    arithmetic::Field,
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
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        // constant vector consists of values in F from 1 to 2^{N_BITS}
        // since we cannot use F::from, so we decided to add this public
        // constant_vector as input
        constant_vector: Vec<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "loading column",
            |mut region| {
                for i in 0..(1 << N_BITS) {
                    region.assign_fixed(
                        || "assigning values to column",
                        self.col,
                        i,
                        || Value::known(constant_vector[i]),
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
