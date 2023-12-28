use super::gadgets::BinaryNumberConfig;
extern crate alloc;
use alloc::vec;
use halo2_proofs::{
    arithmetic::Field,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed},
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

#[derive(Clone, Copy, Debug)]
pub enum LimbIndex {}

// define the columns for the constraint
#[derive(Clone, Copy)]
pub struct Config {
    pub(crate) selector: Column<Fixed>,
    // need to check what does the first_different_limb do before going further
    pub first_different_limb: BinaryNumberConfig<LimbIndex, 5>,
    limb_difference: Column<Advice>,
    limb_difference_inverse: Column<Advice>,
}

impl Config {
    // define the gates for the circuit configuration
    pub fn configure<F: Field>(
        meta: &mut ConstraintSystem<F>,
        powers_of_randomness: [Expression<F>; 31],
    ) -> Self {
        // create selector columns
        let selector = meta.fixed_column();
        let first_different_limb = BinaryNumberChip::configure(meta, selector, None);

        // create advice columns
        let limb_difference = meta.advice_column();
        let limb_difference_inverse = meta.advice_column();

        //initialize the configuration
        let config = Config {
            selector,
            first_different_limb,
            limb_difference,
            limb_difference_inverse,
        };

        // This constraint requires that the limb_difference is not zero. To do this, we
        // consider the inverse of limb_difference, say, limb_difference_inverse and checks
        // that their product is equal to 1.
        meta.create_gate("limb_difference is not zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let limb_difference = meta.query_advice(limb_difference, Rotation::cur());
            let limb_difference_inverse =
                meta.query_advice(limb_difference_inverse, Rotation::cur());
            vec![
                selector
                    * (Expression::Constant(Field::ONE)
                        - limb_difference * limb_difference_inverse),
            ]
        });

        config
    }

    //
    pub fn assign<F: Field>(&self, region: &mut Region<'_, F>) {}
}
