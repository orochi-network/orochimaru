//! Circuit for proving the correctness of the Verkle tree commitment.

extern crate alloc;
use core::marker::PhantomData;

use crate::poseidon::poseidon_hash::{ConstantLength, Hash, Spec};
use alloc::{vec, vec::Vec};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
/// Verkle tree config
pub struct VerkleTreeConfig<F: Field + PrimeField> {
    advice: [Column<Advice>; 2],
    _marker: PhantomData<F>,
}

///
pub(crate) struct VerkleTreeCircuit {}
