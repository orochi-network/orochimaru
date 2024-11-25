use rand::{thread_rng, RngCore};
use tiny_ec::{
    curve::{Affine, Scalar},
    util, SecretKey,
};

use crate::helper::hash_keccak256;

/// Randomize trait allow to generate random value
pub trait Randomize {
    /// Generate random value
    fn random() -> Self;
}

impl Randomize for SecretKey {
    fn random() -> SecretKey {
        let mut rng = thread_rng();
        loop {
            let mut ret = [0u8; util::SECRET_KEY_SIZE];
            rng.fill_bytes(&mut ret);

            if let Ok(key) = Self::parse(&ret) {
                return key;
            }
        }
    }
}

impl Randomize for Scalar {
    fn random() -> Scalar {
        let mut rng = thread_rng();
        let mut ret = [0u8; 32];
        rng.fill_bytes(&mut ret);
        Scalar::from(&ret)
    }
}

/// Hashable trait allow to hash value
pub trait Hashable {
    /// Hash value
    fn keccak256(&self) -> [u8; 32];
}

impl Hashable for Affine {
    fn keccak256(&self) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&self.x.b32());
        buf[32..64].copy_from_slice(&self.y.b32());
        hash_keccak256(&buf)
    }
}

impl Hashable for Scalar {
    fn keccak256(&self) -> [u8; 32] {
        hash_keccak256(&self.b32())
    }
}
