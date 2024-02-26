extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::{iter::once, marker::PhantomData};
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Chip, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
    poly::Rotation,
};
use rand::thread_rng;

use super::gadgets::UTable;

#[derive(Clone, Copy, Debug)]
// define the columns for the constraint
pub struct LexicographicConfig {
    // the difference between the current row and the previous row
    difference: Column<Advice>,
    difference_inverse: Column<Advice>,
    address: [Column<Advice>; 32],
    time_log: [Column<Advice>; 8],
    instruction: Column<Advice>,
    value: [Column<Advice>; 32],
    selector_inverse: Selector,
    selector_first_limb: Selector,
    selector_difference: Selector,
    selector_write: Selector,
}

struct LexicographicChip<F: PrimeField> {
    config: LexicographicConfig,
    _marker: PhantomData<F>,
}

// implement the chip trait
// these functions are not needed
impl<F: PrimeField> Chip<F> for LexicographicChip<F> {
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
impl<F: PrimeField> LexicographicChip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        address: [Column<Advice>; 32],
        time_log: [Column<Advice>; 8],
        instruction: Column<Advice>,
        value: [Column<Advice>; 32],
        u16_table: UTable<16>,
        alpha_power: Vec<Expression<F>>,
    ) -> <Self as Chip<F>>::Config {
        let one = Expression::Constant(F::ONE);

        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let selector_inverse = meta.selector();
        let selector_first_limb = meta.selector();
        let selector_difference = meta.selector();
        let selector_write = meta.selector();

        // inversion gate
        meta.create_gate("difference is non-zero", |meta| {
            let selector_inverse = meta.query_selector(selector_inverse);
            let difference = meta.query_advice(difference, Rotation::cur());
            let difference_inverse = meta.query_advice(difference_inverse, Rotation::cur());
            vec![selector_inverse * (difference * difference_inverse - one)]
        });

        // limbs before first differences are zero
        meta.create_gate("limbs before first differences are zero", |meta| {
            let selector_first_limb = meta.query_selector(selector_first_limb);
            let cur = Queries::new(meta, address, time_log, instruction, value, Rotation::cur());
            let prev = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value,
                Rotation::prev(),
            );
            let mut LIMB_VECTOR = vec![0 as u16];
            for i in 1..40 {
                LIMB_VECTOR.push(i);
            }
            let rlc = rlc_limb_differences(cur, prev, alpha_power);
            let mut constraints = vec![];
            for (i, rlc_expression) in LIMB_VECTOR.iter().zip(rlc) {
                constraints.push(selector_first_limb.clone() * rlc_expression);
            }
            constraints
        });

        // if the current trace is read, then its value must be equal to the previous trace value
        meta.create_gate("if the current trace is read, then its value must be equal to the previous trace value", |meta| {
            let selector_write = meta.query_selector(selector_write);
            let cur = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value, 
                Rotation::cur());
            let prev = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value,  
                Rotation::prev());
            let partial_sum = Expression::Constant(F::ZERO);
            for ((cur_value, prev_value), power_of_randomness) in
                cur.value.iter().zip(prev.value.iter()).zip(alpha_power)
            {
                partial_sum =
                    partial_sum + power_of_randomness * (cur_value.clone() - prev_value.clone());
            }
            vec![selector_write * (cur.instruction - one) * partial_sum]
        });

        // difference equals difference of limbs at index
        meta.create_gate(
            "difference equals difference of limbs at index",
            |meta| {
                let selector_difference = meta.query_selector(selector_difference);
                let cur =
                    Queries::new(meta, address, time_log, instruction, value, Rotation::cur());
                let prev = Queries::new(
                    meta,
                    address,
                    time_log,
                    instruction,
                    value,
                    Rotation::prev(),
                );
                let difference = meta.query_advice(difference, Rotation::cur());
                let mut constraints = vec![];
                for (cur_limb, prev_limb) in cur.be_limbs().iter().zip(&prev.be_limbs()) {
                    constraints.push(
                        selector_difference.clone() * (difference.clone() - *cur_limb + *prev_limb),
                    )
                }
                constraints
            },
        );

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
            address,
            time_log,
            instruction,
            value,
            selector_inverse,
            selector_first_limb,
            selector_difference,
            selector_write,
        }
    }

/*fn assign(
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
        }; */

}

// Returns a vector of length 32 with the rlc of the limb differences between
// from 0 to i-l. 0 for i=0,
fn rlc_limb_differences<F: PrimeField>(
    cur: Queries<F>,
    prev: Queries<F>,
    alpha_power: Vec<Expression<F>>,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = Expression::Constant(F::ZERO);
    let alpha_power = once(Expression::Constant(F::ONE)).chain(alpha_power.into_iter());
    for ((cur_limb, prev_limb), power_of_randomness) in
        cur.be_limbs().iter().zip(&prev.be_limbs()).zip(alpha_power)
    {
        result.push(partial_sum.clone());
        partial_sum = partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
    }
    result
}

#[derive(Default)]
struct LexicographicCircuit<F: PrimeField> {
    address: [Vec<F>; 32],
    time_log: [Vec<F>; 8],
    instruction: Vec<F>,
    value: [Vec<F>; 32],
}

impl<F: PrimeField> Circuit<F> for LexicographicCircuit<F> {
    type Config = LexicographicConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let mut rng = thread_rng();

        let alpha = Expression::Constant(F::random(rng));
        let mut tmp = Expression::Constant(F::ONE);
        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let address = [meta.advice_column(); 32];
        let time_log = [meta.advice_column(); 8];
        let instruction = meta.advice_column();
        let value = [meta.advice_column(); 32];
        let u16_table = UTable::<16>::construct(meta);
        let mut alpha_power: Vec<Expression<F>> = vec![tmp];
        for i in 0..40 {
            tmp = tmp * alpha;
            alpha_power.push(tmp);
        }
        LexicographicChip::configure(
            meta,
            address,
            time_log,
            instruction,
            value,
            u16_table,
            alpha_power,
        )
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

// convert a trace record into a list of element having the form of Expression<F>
struct Queries<F: PrimeField> {
    address: [Expression<F>; 32], //64 bits
    time_log: [Expression<F>; 8], //64 bits
    instruction: Expression<F>,   // 0 or 1
    value: [Expression<F>; 32],   //64 bit
}

impl<F: PrimeField> Queries<F> {
    // converts the attributes of a trace record to type Expression<F>
    fn new(
        meta: &mut VirtualCells<'_, F>,
        address: [Column<Advice>; 32],
        time_log: [Column<Advice>; 8],
        instruction: Column<Advice>,
        value: [Column<Advice>; 32],
        rotation: Rotation,
    ) -> Self {
        let mut query_advice = |column| meta.query_advice(column, rotation);
        Self {
            address: address.map(&mut query_advice),
            time_log: time_log.map(&mut query_advice),
            instruction: query_advice(instruction),
            value: value.map(&mut query_advice),
        }
    }

    // stack address and time_log into a single array for comparison
    fn be_limbs(&self) -> Vec<Expression<F>> {
        self.address
            .iter()
            .rev()
            .chain(self.time_log.iter().rev())
            .cloned()
            .collect()
    }
}
