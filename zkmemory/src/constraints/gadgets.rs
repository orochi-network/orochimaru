extern crate alloc;
use alloc::{format, vec::Vec};
use core::marker::PhantomData;
use halo2_proofs::{
    arithmetic::Field,
    circuit::Region,
    plonk::{Advice, Column, Expression, VirtualCells},
    poly::Rotation,
};

// this file contains the auxiliary components which are necessary for
// implementing the functions in permutation checks and lexicographic ordering

/// Helper trait that implements functionality to represent a generic type as
/// array of N-bits.
pub trait AsBits<const N: usize> {
    /// Return the bits of self, starting from the most significant.
    fn as_bits(&self) -> [bool; N];
}

impl<T, const N: usize> AsBits<N> for T
where
    T: Copy + Into<usize>,
{
    fn as_bits(&self) -> [bool; N] {
        let mut bits = [false; N];
        let mut x: usize = (*self).into();
        for i in 0..N {
            bits[N - 1 - i] = x % 2 == 1;
            x /= 2;
        }
        bits
    }
}

/// Config for the binary number chip.
#[derive(Clone, Copy, Debug)]
pub struct BinaryNumberConfig<T, const N: usize> {
    /// Must be constrained to be binary for correctness.
    pub bits: [Column<Advice>; N],
    _marker: PhantomData<T>,
}

impl<T, const N: usize> BinaryNumberConfig<T, N>
where
    T: AsBits<N>,
{
    /// Returns the expression value of the bits at the given rotation.
    pub fn value<F: Field>(
        &self,
        rotation: Rotation,
    ) -> impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F> {
        let bits = self.bits;
        move |meta: &mut VirtualCells<'_, F>| {
            let bits = bits.map(|bit| meta.query_advice(bit, rotation));
            bits.iter()
                .fold(0.expr(), |result, bit| bit.clone() + result * 2.expr())
        }
    }

    /// Return the constant that represents a given value. To be compared with the value expression.
    pub fn constant_expr<F: Field>(&self, value: T) -> Expression<F> {
        let f = value.as_bits().iter().fold(
            F::ZERO,
            |result, bit| if *bit { F::ONE } else { F::ZERO } + result * F::from(2),
        );
        Expression::Constant(f)
    }

    /// Returns a function that can evaluate to a binary expression, that
    /// evaluates to 1 if value is equal to value as bits. The returned
    /// expression is of degree N.
    pub fn value_equals<F: Field, S: AsBits<N>>(
        &self,
        value: S,
        rotation: Rotation,
    ) -> impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F> {
        let bits = self.bits;
        move |meta| Self::value_equals_expr(value, bits.map(|bit| meta.query_advice(bit, rotation)))
    }

    /// Returns a binary expression that evaluates to 1 if expressions are equal
    /// to value as bits. The returned expression is of degree N.
    pub fn value_equals_expr<F: Field, S: AsBits<N>>(
        value: S,
        expressions: [Expression<F>; N], // must be binary.
    ) -> Expression<F> {
        and::expr(
            value
                .as_bits()
                .iter()
                .zip(&expressions)
                .map(|(&bit, expression)| {
                    if bit {
                        expression.clone()
                    } else {
                        not::expr(expression.clone())
                    }
                }),
        )
    }

    /// Annotates columns of this gadget embedded within a circuit region.
    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<'_, F>, prefix: &str) {
        let mut annotations = Vec::new();
        for (i, _) in self.bits.iter().enumerate() {
            annotations.push(format!("GADGETS_binary_number_{}", i));
        }
        self.bits
            .iter()
            .zip(annotations.iter())
            .for_each(|(col, ann)| region.name_column(|| format!("{}_{}", prefix, ann), *col));
    }
}

#[derive(Clone, Debug)]
pub struct BinaryNumberChip<F, T, const N: usize> {
    config: BinaryNumberConfig<T, N>,
    _marker: PhantomData<F>,
}
