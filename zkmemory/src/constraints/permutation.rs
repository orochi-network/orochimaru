use group::ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use core::marker::PhantomData;

// Define instructions used in the circuit
// Includes: load_private, load_constant, add, mul, and expose_public.
trait NumericInstructions<F: Field>: Chip<F> {
    type Num;

    /// Loads a private input into a circuit.
    fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;

    /// Loads a fixed constant into a circuit.
    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;

    /// Adds a and b, returns c = a + b.
    /// In the newer version of Halo2, a or b can also be a constant.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Multiplies a and b, returns c = a * b.
    /// In the newer version of Halo2, a or b can also be a constant.
    fn mul(
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

// Define that chip config struct
#[derive(Clone, Debug)]
struct PermutationConfig {
    // Input: an array of field elements
    input: Column<Advice>,
    // Output: an array of shuffled field elements of input
    output: Column<Advice>,
}

impl<F: Field> PermutationChip<F> {
    
    // Construct a permutation chip using the config
    fn construct(config: PermutationConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

fn main() {

    // Test params of the permutation circuit example
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    const K: u32 = 4;
    let input_0 = [1, 2, 4, 1]
        .map(|e: u64| Value::known(Fp::from(e)))
        .to_vec();
    let input_1 = [10, 20, 40, 10].map(Fp::from).to_vec();
    let shuffle_0 = [4, 1, 1, 2]
        .map(|e: u64| Value::known(Fp::from(e)))
        .to_vec();
    let shuffle_1 = [40, 10, 10, 20]
        .map(|e: u64| Value::known(Fp::from(e)))
        .to_vec();
}
