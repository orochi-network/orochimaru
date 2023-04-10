use halo2_proofs::poly::commitment::CommitmentScheme;

/// Multiple provers as backend
pub enum Commitment {
    KZG,
    Merkle,
    Verkle,
}

pub trait DummyCommitmentScheme {
    fn new() -> Self;
}

#[derive(Debug, Clone)]
pub struct DummyCommitment {}

impl DummyCommitmentScheme for DummyCommitment {
    fn new() -> Self {
        Self {}
    }
}
