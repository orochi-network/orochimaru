use ff::PrimeField;

/// A trait defining a common interface for commitment schemes with zk proving capabilities
pub trait CommitmentScheme<F: PrimeField> { // TODO: add traitbound : Circuit<F> after kzg is finalized
    /// The commitment
    type Commitment;
    /// The type of the opening (proof)
    type Opening;
    /// The type of additional data needed for verification (e.g., Merkle path or evaluation point)
    type Witness;
    /// The type of public parameters (if needed)
    type PublicParams;

    /// Setup the commitment scheme
    fn setup(k: u32) -> Self::PublicParams;

    /// Commit to a value
    fn commit(pp: Self::PublicParams, witness: Self::Witness) -> Self::Commitment;

    /// Open a commitment
    fn open(pp: Self::PublicParams, witness: Self::Witness) -> Self::Opening;

    /// Verify a commitment
    fn verify(
        pp: Self::PublicParams,
        commitment: Self::Commitment,
        opening: Self::Opening,
        witness: Self::Witness,
    ) -> bool;
}