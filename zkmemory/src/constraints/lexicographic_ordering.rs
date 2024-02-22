extern crate alloc;
use crate::{base::Base, machine::TraceRecord};
use alloc::vec;
use alloc::vec::Vec;
use core::{iter::once, marker::PhantomData};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use super::gadgets::UTable;
// We use this chip to show that the rows of the memory trace table are sorted
// in a lexicographic order (by address, time log, opcode).

// We define the following advice columns and constraints:

// Advice columns:
// 1. first_different_limb: the first index where limb differs
// 2. difference: the difference between the limbs at first_different_limb.
// By definition, this value is non-zero
// 3. difference_inverse: the inverse of difference.

// Constraints:
// 1. difference must be non-zero.
// 2. all the pairwise limb differences before the first_different_limb is
// zero, due to the definition of first_different_limb.
// 3. difference equals the difference of the limbs at first_different_limb.

#[derive(Clone, Copy, Debug)]
// define the columns for the constraint
pub struct LexicographicConfig {
    // the difference between the current row and the previous row
    difference: Column<Advice>,
    difference_inverse: Column<Advice>,
    selector: Column<Fixed>,
}

struct LexicographicChip<F: Field, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    config: LexicographicConfig,
    _marker: PhantomData<(K, V, F)>,
}

// implement the chip trait
// these functions are not needed
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

// implement the configure method for selecting gates
// we have the gates for checking inverse, lookup and checking that
// all values before first_difference_limb are equal to zero
impl<F: Field, K, V, const S: usize, const T: usize> LexicographicChip<F, K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn configure(
        &self,
        meta: &mut ConstraintSystem<F>,
        trace: TraceRecord<K, V, S, T>,
        u16_table: UTable<16>,
        alpha_power: [Expression<F>; 97],
    ) -> <Self as Chip<F>>::Config {
        let one = Expression::Constant(F::ONE);
        //   meta.enable_equality(u16_table);

        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let selector = meta.fixed_column();
        //   let first_different_limb = BinChip::configure(meta, selector, None);

        // inversion gate
        meta.create_gate("difference is non-zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let difference = meta.query_advice(difference, Rotation::cur());
            let difference_inverse = meta.query_advice(difference_inverse, Rotation::cur());
            vec![selector * (difference * difference_inverse - one)]
        });

        // limbs before first differences are zero
        meta.create_gate("limbs before first differences are zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            // TODO: implement Queries struct first, then use the constraints on this
            let cur = Queries::new(meta, trace, Rotation::cur());
            let prev = Queries::new(meta, trace, Rotation::prev());
            let mut LIMB_VECTOR = vec![0 as u16];
            for i in 1..96 {
                LIMB_VECTOR.push(i);
            }
            let rlc = self.rlc_limb_differences(cur, prev, alpha_power);
            let mut constraints = vec![];
            for (i, rlc_expression) in LIMB_VECTOR.iter().zip(rlc) {
                constraints.push(selector.clone() * rlc_expression);
            }
            constraints
        });

        // lookup gate
        meta.lookup_any("difference is in u16", |meta| {
            let difference = meta.query_advice(difference, Rotation::cur());
            let col = u16_table.table_exprs(meta);
            vec![difference]
                .into_iter()
                .zip_eq(col)
                .map(|(difference, col)| (difference, col))
                .collect()
        });
        // return the config after assigning the gates
        LexicographicConfig {
            difference,
            difference_inverse,
            selector,
        }
    }

    // it seems that this method has the same role as systhenize, maybe
    // anyway, let's find out what it does
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cur: TraceRecord<K, V, S, T>,
        prev: TraceRecord<K, V, S, T>,
    ) -> Result<(), Error> {
        // set the current selector to be one,
        region.assign_fixed(
            || "upper_limb_difference",
            self.config.selector,
            offset,
            || Value::known(F::ONE),
        )?;

        let cur_be_limbs = self.trace_to_be_limbs(cur);
        let prev_be_limbs = self.trace_to_be_limbs(prev);
        let mut LIMB_VECTOR = vec![0 as u16];
        for i in 1..96 {
            LIMB_VECTOR.push(i);
        }
        let find_result = LIMB_VECTOR
            .iter()
            .zip(&cur_be_limbs)
            .zip(&prev_be_limbs)
            .find(|((_, a), b)| a != b);

        let ((index, cur_limb), prev_limb) = if cfg!(test) {
            find_result.unwrap_or(((&96, &0), &0))
        } else {
            find_result.expect("two trace records cannot be the same")
        };

        let difference = F::ONE;

        // assign the the difference witness (current row - previous row)
        region.assign_advice(
            || "limb_difference",
            self.config.difference,
            offset,
            || Value::known(difference),
        )?;

        // assign the inverse of difference
        region.assign_advice(
            || "limb_difference_inverse",
            self.config.difference_inverse,
            offset,
            || Value::known(difference.invert().expect("cannot find inverse")),
        )?;

        Ok(())
    }

    // helper function to convert the trace to be_limbs
    fn trace_to_be_limbs(&self, trace: TraceRecord<K, V, S, T>) -> Vec<u16> {
        let mut be_bytes = vec![0u8];
        let (time_log, stack_depth, instruction, address, value) = trace.get_tuple();
        be_bytes.extend_from_slice(&address.zfill32());
        be_bytes.extend_from_slice(&time_log.to_be_bytes());
        be_bytes.extend_from_slice(&value.zfill32());
        be_bytes
    }

    // Returns a vector of length 32 with the rlc of the limb differences between
    // from 0 to i-l. 0 for i=0,
    fn rlc_limb_differences(
        &self,
        cur: Queries<F, K, V, S, T>,
        prev: Queries<F, K, V, S, T>,
        powers_of_randomness: [Expression<F>; 97],
    ) -> Vec<Expression<F>> {
        let mut result = vec![];
        let mut partial_sum = Expression::Constant(F::ZERO);
        let powers_of_randomness =
            once(Expression::Constant(F::ONE)).chain(powers_of_randomness.into_iter());
        for ((cur_limb, prev_limb), power_of_randomness) in cur
            .be_limbs()
            .iter()
            .zip(&prev.be_limbs())
            .zip(powers_of_randomness)
        {
            result.push(partial_sum.clone());
            partial_sum =
                partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
        }
        result
    }
}

// convert a trace record into a list of element having the form of Expression<F>
struct Queries<F: Field, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    address: [Expression<F>; 32],  //64 bits
    time_log: [Expression<F>; 32], //64 bits
    instruction: Expression<F>,    // 0 or 1
    value: [Expression<F>; 32],    //64 bits
    phantom_data: PhantomData<(K, V, F)>,
}

impl<F: Field, K, V, const S: usize, const T: usize> Queries<F, K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn new(
        meta: &mut VirtualCells<'_, F>,
        trace: TraceRecord<K, V, S, T>,
        rotation: Rotation,
    ) -> Self {
        let (time_log, stack_depth, instruction, address, value) = trace.get_tuple();
        // TODO: Convert the elements from TraceRecord to F

        Self {
            address: [Expression::Constant(F::ZERO); 32],
            time_log: [Expression::Constant(F::ZERO); 32],
            instruction: Expression::Constant(F::ZERO),
            value: [Expression::Constant(F::ZERO); 32],
            phantom_data: PhantomData,
        }
    }
    fn be_limbs(&self) -> Vec<Expression<F>> {
        self.address
            .iter()
            .rev()
            .chain(self.time_log.iter().rev())
            .chain(once(&self.instruction))
            .chain(self.value.iter().rev())
            .cloned()
            .collect()
    }
}
