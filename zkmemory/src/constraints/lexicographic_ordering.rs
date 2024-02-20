extern crate alloc;
use crate::{
    base::{Base, B256},
    machine::TraceRecord,
};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
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
// #[derive(Clone, Copy)]
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
        meta: &mut ConstraintSystem<F>,
        trace: TraceRecord<K, V, S, T>,
        u16_table: UTable<16>,
        alpha_power: [Expression<F>; 31],
    ) -> <Self as Chip<F>>::Config {
        let one = Expression::Constant(F::ONE);
        //   meta.enable_equality(u16_table);

        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let selector = meta.fixed_column();

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
            vec![]
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

        let cur_be_limbs = trace_to_be_limbs(cur);
        let prev_be_limbs = trace_to_be_limbs(prev);

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
        let mut query_advice = |column| meta.query_advice(column, rotation);
        let (time_log, stack_depth, instruction, address, value) = trace.get_tuple();
        Self {
            address: address.map(&query_advice),
            time_log: time_log.map(&query_advice),
            instruction: instruction.map(&query_advice),
            value: value.map(&query_advice),
            phantom_data: PhantomData,
        }
    }
}

fn trace_to_be_limbs(trace: TraceRecord<B256, B256, 32, 32>) -> Vec<u16> {
    let mut be_bytes = vec![0u8];
    let (time_log, stack_depth, instruction, address, value) = trace.get_tuple();
    be_bytes.extend_from_slice(&address.zfill32());
    be_bytes.extend_from_slice(&time_log.to_be_bytes());
    be_bytes.extend_from_slice(&value.zfill32());
    be_bytes
}
