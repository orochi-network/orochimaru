// An ambition is hiding in the bush
use libsecp256k1::{
    curve::{Affine, Field, Scalar},
    PublicKey,
};

#[derive(Clone, Copy, Debug)]
pub struct ECVRFProof {
    pub gamma: Affine,
    pub c: Scalar,
    pub s: Scalar,
    pub y: Scalar,
    pub pk: PublicKey,
}

#[derive(Clone, Copy, Debug)]
pub struct ECVRFContractProof {
    pub pk: PublicKey,
    pub gamma: Affine,
    pub c: Scalar,
    pub s: Scalar,
    pub y: Scalar,
    pub alpha: Scalar,
    pub witness_address: Scalar,
    pub witness_gamma: Affine,
    pub witness_hash: Affine,
    pub inverse_z: Field,
}

impl ECVRFProof {
    pub fn new(gamma: Affine, c: Scalar, s: Scalar, y: Scalar, pk: PublicKey) -> Self {
        Self { gamma, c, s, y, pk }
    }
}
