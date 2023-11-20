extern crate alloc;
use crate::helper::random_bytes;
use alloc::string::String;
use libsecp256k1::curve::{Affine, Field, Jacobian, Scalar};
use tiny_keccak::{Hasher, Keccak};

/// Extend Affine
pub trait AffineExtend {
    /// Compose Affine for its coordinate X,Y
    fn compose(x: &Field, y: &Field) -> Self;

    /// Create Affine from Jacobian
    fn from_jacobian(j: &Jacobian) -> Self;

    /// Serialize Affine to hex string
    fn to_hex_string(&self) -> String;

    /// Keccak Affine to bytes array
    fn keccak256(&self) -> [u8; 32];
}

/// Extend Scalar
pub trait ScalarExtend {
    /// Create Scalar from bytes array
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Randomize Scalar
    fn randomize() -> Self;

    /// Keccak a vector to scalar
    fn keccak256(a: &[u8]) -> Self;

    /// Make sure self > b
    fn gt(&self, b: &Scalar) -> bool;

    /// Make sure self >= b
    fn gte(&self, b: &Scalar) -> bool;
}

impl AffineExtend for Affine {
    fn compose(x: &Field, y: &Field) -> Self {
        let mut r = Affine::default();
        r.set_xy(x, y);
        r.x.normalize();
        r.y.normalize();
        r
    }

    fn to_hex_string(&self) -> String {
        hex::encode([self.x.b32(), self.y.b32()].concat())
    }

    fn keccak256(&self) -> [u8; 32] {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(self.x.b32().as_ref());
        hasher.update(self.y.b32().as_ref());
        hasher.finalize(&mut output);
        output
    }

    fn from_jacobian(j: &Jacobian) -> Self {
        let mut ra = Affine::from_gej(j);
        ra.x.normalize();
        ra.y.normalize();
        ra
    }
}

impl ScalarExtend for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() > 32 {
            panic!("Bytes length must be less than 32")
        }
        let mut tmp_bytes = [0u8; 32];
        tmp_bytes[0..bytes.len()].copy_from_slice(bytes);
        let mut r = Scalar::default();
        r.set_b32(&tmp_bytes).unwrap_u8();
        r
    }

    /// Return true if a > b
    fn gt(&self, b: &Scalar) -> bool {
        for i in (0..self.0.len()).rev() {
            if self.0[i] < b.0[i] {
                return false;
            }
            if self.0[i] > b.0[i] {
                return true;
            }
        }
        false
    }

    /// Return true if a >= b
    fn gte(&self, b: &Scalar) -> bool {
        for i in (0..self.0.len()).rev() {
            if self.0[i] < b.0[i] {
                return false;
            }
            if self.0[i] > b.0[i] {
                return true;
            }
        }
        true
    }

    fn keccak256(a: &[u8]) -> Self {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(a);
        hasher.finalize(&mut output);
        Self::from_bytes(&output)
    }

    fn randomize() -> Self {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf);
        Self::from_bytes(&buf)
    }
}
