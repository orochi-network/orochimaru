use ff::PrimeField;
use halo2_proofs::plonk::Circuit;
use std::error::Error;

/// A trait defining a common interface for commitment schemes with zk proving capabilities
pub trait CommitmentScheme<F: PrimeField>: Circuit<F> {
    /// The type of the committed value
    type Value;
    /// The type of the commitment
    type Commitment;
    /// The type of the opening (proof)
    type Opening;
    /// The type of additional data needed for verification (e.g., Merkle path or evaluation point)
    type Witness;
    /// The type of public parameters (if needed)
    type PublicParams;

    type Prover;

    type Verifier;

    type Instance;

    /// Setup the commitment scheme
    fn setup(k: u32) -> Result<Self::PublicParams, Box<dyn Error>>;

    /// Commit to a value
    fn commit(
        // &mut self,
        pp: &Self::PublicParams,
        value: &Self::Value,
    ) -> Result<Self::Commitment, Box<dyn Error>>;

    /// Open a commitment
    fn open(
        pp: &Self::PublicParams,
        instance: &Self::Instance,
        prover: Self::Prover,
    ) -> Result<Self::Opening, Box<dyn Error>>;

    /// Verify a commitment
    fn verify(
        opening: &Self::Opening,
        instance: &Self::Instance,
        verifier: Self::Verifier,
    ) -> Result<bool, Box<dyn Error>>;
}
