extern crate alloc;
use crate::{base::Base, machine::TraceRecord};
use alloc::{format, vec};
use core::marker::PhantomData;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
// We use this chip to show that the rows of the memory trace table are sorted
// in a lexicographic order (by address, time log, opcode).

// We define the following advice columns and constraints:

// Advice columns:
// 1. first_different_limb: the first index where limb differs
// 2. limb_difference: the difference between the limbs at first_different_limb.
// By definition, this value is non-zero
// 3. limb_difference_inverse: the inverse of limb_difference.

// Constraints:
// 1. limb_difference must be non-zero.
// 2. all the pairwise limb differences before the first_different_limb is
// zero, due to the definition of first_different_limb.
// 3. limb_difference equals the difference of the limbs at first_different_limb.

#[derive(Clone, Copy, Debug)]
// define the columns for the constraint
// #[derive(Clone, Copy)]
pub struct LexicographicConfig {
    // the difference between the current row and the previous row
    difference: Column<Advice>,
    difference_inverse: Column<Advice>,
    // selector for the inversion constraint
    sel_inv: Selector,
}

struct LexicographicChip<F: Field, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    config: LexicographicConfig,
    _marker: PhantomData<(K, V, F)>,
}

impl<F: Field, K, V, const S: usize, const T: usize> Chip<F> for LexicographicChip<F, K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    type Config = LexicographicConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field, K, V, const S: usize, const T: usize> LexicographicChip<F, K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        trace: TraceRecord<K, V, S, T>,
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) {
        let one = Expression::Constant(F::ONE);
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }

        let sel_inv = meta.selector();

        meta.create_gate("difference is non-zero", |meta| {
            let sel_inv = meta.query_selector(sel_inv);
            let difference = meta.query_advice(advice[0], Rotation::cur());
            let difference_inverse = meta.query_advice(advice[1], Rotation::cur());
            vec![sel_inv * (difference * difference_inverse - one)]
        });
    }
}
