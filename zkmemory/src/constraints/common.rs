use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Circuit, Error},
};
/// the fuck
pub trait CircuitExtension<F>
where
    F: Field + PrimeField,
    Self: Circuit<F>,
{
    /// the fuck part 2
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;
}
