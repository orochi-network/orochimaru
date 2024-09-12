extern crate alloc;
use alloc::{vec::Vec, boxed::Box};
use core::error::Error;
use ff::PrimeField;
use halo2_proofs::plonk::Circuit;

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

    /// Setup the commitment scheme
    fn setup(k: u32) -> Result<Self::PublicParams, Box<dyn Error>>;

    /// Commit to a value
    fn commit(pp: &Self::PublicParams, value: &Self::Value) -> Result<Self::Commitment, Box<dyn Error>>;

    /// Open a commitment
    fn open(pp: &Self::PublicParams, value: &Self::Value, witness: &Self::Witness) -> Result<Self::Opening, Box<dyn Error>>;

    /// Verify a commitment
    fn verify(
        pp: &Self::PublicParams,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        witness: &Self::Witness,
    ) -> Result<bool, Box<dyn Error>>;

    /// Create a proof for the commitment scheme
    fn create_proof(pp: &Self::PublicParams, circuit: Self) -> Result<Vec<u8>, Box<dyn Error>>;

}