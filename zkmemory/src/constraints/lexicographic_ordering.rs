use super::gadgets::BinaryNumberConfig;
extern crate alloc;
use alloc::{format, vec};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed},
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
        // that their product is equal to 1, done.
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

        // This constraint requires all the pairwise limb differences before the first_different_limb
        // is zero. To do this, we sample a randomness r and check if
        // (cur_1 - prev_1) + r(cur_2 - prev_2) + r^2(cur_3 - prev_3) + r^3(cur_4 - prev_4) = 0
        // with r sampled, then the condition holds with overwhelming probability
        // need to understand what these lines do

        meta.create_gate(
            "limb differences before first_different_limb are all 0",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let mut constraints = vec![];
                constraints
            },
        );

        // This constraint requires that the limb_difference is equal to the difference of limbs
        // at index
        meta.create_gate(
            "limb_difference equals difference of limbs at index",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let mut constraints = vec![];
                constraints
            },
        );
        config
    }

    // Returns true if the `cur` row is a first access to a group (at least one of
    // address, time log, opcode is different from 'prev'), and false otherwise
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<LimbIndex, Error> {
        region.assign_fixed(
            || "upper_limb_difference",
            self.selector,
            offset,
            || Value::known(F::ONE),
        )?;
    }

    /// Annotates columns of this gadget embedded within a circuit region.
    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<'_, F>, prefix: &str) {
        [
            (self.limb_difference, "LO_limb_difference"),
            (self.limb_difference_inverse, "LO_limb_difference_inverse"),
        ]
        .iter()
        .for_each(|(col, ann)| region.name_column(|| format!("{}_{}", prefix, ann), *col));
        // fixed column
        region.name_column(
            || format!("{}_LO_upper_limb_difference", prefix),
            self.selector,
        );
    }
}
