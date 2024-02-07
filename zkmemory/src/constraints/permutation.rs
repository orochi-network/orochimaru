use std::marker::PhantomData;
use group::ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};

// Define instructions used in the circuit
// Includes: load_private, load_constant, add, mul, and expose_public.
trait NumericInstructions<F: Field>: Chip<F> {
    
    type Num;

    /// Loads a private input into a circuit.
    fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;

    /// Loads a fixed constant into a circuit.
    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;

    /// Adds a and b, returns c = a + b.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Multiplies a and b, returns c = a * b.
    fn muls(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Exposes a number as a public input to the circuit.
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;

}

// Define a chip struct that implements our instructions.
struct PermutationChip<F: Field> {
    config: PermutationConfig,
    _marker: PhantomData<F>,
}
