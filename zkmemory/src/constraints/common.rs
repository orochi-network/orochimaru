use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Circuit, Error},
};

pub trait CircuitExtension<F>
where
    F: Field + PrimeField,
    Self: Circuit<F>,
{
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;
}
