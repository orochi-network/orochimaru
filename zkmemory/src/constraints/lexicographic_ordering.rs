extern crate alloc;
use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use group::Curve;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};
use rand_core::OsRng;
// We use this chip to show that the rows of the memory trace table are sorted
// in a lexicographic order (by address, time log, opcode).

// We define the following advice columns and constraints:

// Advice columns:
// 1. first_different_limb:
// 2. limb_difference:
// 3. limb_difference_inverse: the inverse of limb_difference.

// Constraints:

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
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
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
    }

    //
    pub fn assign<F: Field>(&self, region: &mut Region<'_, F>) -> Result<(), Error> {}
}
extern crate alloc;
use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use group::Curve;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};
use rand_core::OsRng;
// We use this chip to show that the rows of the memory trace table are sorted
// in a lexicographic order (by address, time log, opcode).

// We define the following advice columns and constraints:

// Advice columns:
// 1. first_different_limb:
// 2. limb_difference:
// 3. limb_difference_inverse: the inverse of limb_difference.

// Constraints:

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
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
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
    }

    //
    pub fn assign<F: Field>(&self, region: &mut Region<'_, F>) -> Result<(), Error> {}
}
