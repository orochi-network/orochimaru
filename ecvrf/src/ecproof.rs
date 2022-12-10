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

impl ToString for ECVRFProof {
    fn to_string(&self) -> String {
        let mut pub_affine: Affine = self.pk.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();
        format!(
            "gamma: x: 0x{}\n > y: 0x{}\nc: 0x{}\ns: 0x{}\ny: 0x{}\npublic key:\n > x: {}\n > y: {}\n",
            hex::encode(self.gamma.x.b32()),
            hex::encode(self.gamma.y.b32()),
            hex::encode(self.c.b32()),
            hex::encode(self.s.b32()),
            hex::encode(self.y.b32()),
            hex::encode(pub_affine.x.b32()),
            hex::encode(pub_affine.y.b32())
        )
    }
}
