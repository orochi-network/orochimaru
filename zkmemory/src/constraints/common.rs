use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Circuit, Error},
};
/// A common trait for synthesizing the circuit
pub trait CircuitExtension<F>
where
    F: Field + PrimeField,
    Self: Circuit<F>,
{
    /// Synthesize with layouter
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;
}
