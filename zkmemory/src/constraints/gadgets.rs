extern crate alloc;
use core::marker::PhantomData;

use alloc::vec::Vec;
use alloc::{collections::BTreeSet, vec};
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
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

/// Helper trait that implements functionality to represent a generic type as
/// array of N-bits.
pub trait AsBits<const N: usize> {
    /// Return the bits of self, starting from the most significant.
    fn as_bits(&self) -> [bool; N];
}

// A config of binary number. Used as a sub-config
#[derive(Clone, Copy, Debug)]
pub struct BinConfig<T, const N: usize> {
    /// Must be constrained to be binary for correctness.
    pub bits: [Column<Advice>; N],
    _marker: PhantomData<T>,
}

// the chip of the binary number
#[derive(Clone, Debug)]
pub struct BinChip<F, T, const N: usize> {
    config: BinConfig<T, N>,
    _marker: PhantomData<F>,
}

impl<F: Field, T: IntoEnumIterator, const N: usize> BinChip<F, T, N>
where
    T: AsBits<N>,
{
    /// Construct the binary number chip given a config.
    pub fn construct(config: BinConfig<T, N>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
    /// Configure constraints for the binary number chip.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Column<Fixed>,
        value: Option<Column<Advice>>,
    ) -> BinConfig<T, N> {
        let bits = [0; N].map(|_| meta.advice_column());
        bits.map(|bit| {
            meta.create_gate("bit column is 0 or 1", |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let bit = meta.query_advice(bit, Rotation::cur());
                vec![selector * bit.clone() * (Value::known(F::ONE) - bit)]
            })
        });

        let config = BinConfig {
            bits,
            _marker: PhantomData,
        };

        if let Some(value) = value {
            meta.create_gate("binary number value", |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                vec![
                    selector
                        * (config.value(Rotation::cur())(meta)
                            - meta.query_advice(value, Rotation::cur())),
                ]
            });
        }

        // Disallow bit patterns (if any) that don't correspond to a variant of T.
        let valid_values: BTreeSet<usize> = T::iter().map(|t| from_bits(&t.as_bits())).collect();
        let mut invalid_values = (0..1 << N).filter(|i| !valid_values.contains(i)).peekable();
        if invalid_values.peek().is_some() {
            meta.create_gate("binary number value in range", |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                invalid_values
                    .map(|i| {
                        let value_equals_i = config.value_equals(i, Rotation::cur());
                        selector.clone() * value_equals_i(meta)
                    })
                    .collect::<Vec<_>>()
            });
        }

        config
    }
}

/// Helper function to get a decimal representation given the bits.
pub fn from_bits(bits: &[bool]) -> usize {
    bits.iter()
        .fold(0, |result, &bit| bit as usize + 2 * result)
}
