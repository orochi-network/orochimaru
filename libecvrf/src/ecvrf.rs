extern crate alloc;
use crate::{
    error,
    extends::{AffineExtend, ScalarExtend},
    hash::{hash_points, hash_points_prefix, hash_to_curve, hash_to_curve_prefix},
    helper::*,
};
use alloc::string::String;
use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar, AFFINE_G},
    util::{FULL_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE},
    PublicKey, SecretKey, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT,
};
use rand::thread_rng;

/// Max retries for randomize scalar or repeat hash
pub const MAX_RETRIES: u32 = 100;

/// Zeroable trait
pub trait Zeroable {
    /// Zeroize self
    fn zeroize(&mut self);
    /// Check self is zero or not
    fn is_zero(&self) -> bool;
}

#[derive(Debug, Eq, PartialEq)]
/// Key pair
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

#[derive(Debug, Eq, PartialEq)]
/// Raw key pair
pub struct RawKeyPair {
    /// Raw public key
    pub public_key: [u8; FULL_PUBLIC_KEY_SIZE],
    /// Raw secret key
    pub secret_key: [u8; SECRET_KEY_SIZE],
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    /// Generate a new key pair
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = SecretKey::random(&mut rng);
        let public_key = PublicKey::from_secret_key(&secret_key);
        KeyPair {
            public_key,
            secret_key,
        }
    }
}

impl Zeroable for RawKeyPair {
    fn zeroize(&mut self) {
        for i in 0..self.public_key.len() {
            self.public_key[i] ^= self.public_key[i];
        }

        for i in 0..self.secret_key.len() {
            self.secret_key[i] ^= self.secret_key[i];
        }
    }

    fn is_zero(&self) -> bool {
        for i in 0..self.public_key.len() {
            if self.public_key[i] != 0 {
                return false;
            }
        }

        for i in 0..self.secret_key.len() {
            if self.secret_key[i] != 0 {
                return false;
            }
        }
        true
    }
}

impl From<SecretKey> for KeyPair {
    fn from(value: SecretKey) -> Self {
        KeyPair {
            public_key: PublicKey::from_secret_key(&value),
            secret_key: value,
        }
    }
}

impl From<&[u8; SECRET_KEY_SIZE]> for KeyPair {
    fn from(value: &[u8; SECRET_KEY_SIZE]) -> Self {
        let secret_instance = SecretKey::parse(value).expect("Can not parse secret key");
        KeyPair {
            public_key: PublicKey::from_secret_key(&secret_instance),
            secret_key: secret_instance,
        }
    }
}

impl From<String> for KeyPair {
    fn from(value: String) -> Self {
        let mut secret_key = [0u8; SECRET_KEY_SIZE];
        hex::decode_to_slice(value.trim(), &mut secret_key)
            .expect("Unable to convert secret key to [u8; SECRET_KEY_SIZE]");
        Self::from(&secret_key)
    }
}

impl From<&KeyPair> for RawKeyPair {
    fn from(value: &KeyPair) -> Self {
        RawKeyPair {
            public_key: value.public_key.serialize(),
            secret_key: value.secret_key.serialize(),
        }
    }
}

impl From<&[u8; SECRET_KEY_SIZE]> for RawKeyPair {
    fn from(value: &[u8; SECRET_KEY_SIZE]) -> Self {
        let secret_instance = SecretKey::parse(value).expect("Can not parse secret key");
        let public_key = PublicKey::from_secret_key(&secret_instance).serialize();
        RawKeyPair {
            public_key,
            secret_key: *value,
        }
    }
}

/// EC-VRF proof
#[derive(Clone, Copy, Debug)]
pub struct ECVRFProof {
    /// gamma
    pub gamma: Affine,
    /// c
    pub c: Scalar,
    /// s
    pub s: Scalar,
    /// y is the result
    pub y: Scalar,
    /// Public key
    pub pk: PublicKey,
}

/// EC-VRF contract proof that compatible and verifiable with Solidity contract
#[derive(Clone, Copy, Debug)]
pub struct ECVRFContractProof {
    /// Public key
    pub pk: PublicKey,
    /// gamma
    pub gamma: Affine,
    /// c
    pub c: Scalar,
    /// s
    pub s: Scalar,
    /// Result y
    pub y: Scalar,
    /// Seed alpha
    pub alpha: Scalar,
    /// Witness address
    pub witness_address: Scalar,
    /// Witness gamma
    pub witness_gamma: Affine,
    /// Witness hash
    pub witness_hash: Affine,
    /// Inverse z, easier to verify in Solidity
    pub inverse_z: Field,
}

/// ECVRF
pub struct ECVRF<'a> {
    secret_key: SecretKey,
    public_key: PublicKey,
    ctx_mul: &'a ECMultContext,
    ctx_gen: &'a ECMultGenContext,
}

impl<'a> ECVRF<'a> {
    /// Create new instance of ECVRF from a secret key
    pub fn new(secret_key: SecretKey) -> Self {
        ECVRF {
            secret_key,
            public_key: PublicKey::from_secret_key(&secret_key),
            ctx_gen: &ECMULT_GEN_CONTEXT,
            ctx_mul: &ECMULT_CONTEXT,
        }
    }

    /// We use this method to prove a randomness for L1 smart contract
    /// This prover was optimized for on-chain verification
    /// u_witness is a represent of u, used ecrecover to minimize gas cost
    /// we're also add projective EC add to make the proof compatible with
    /// on-chain verifier.
    pub fn prove_contract(&self, alpha: &Scalar) -> Result<ECVRFContractProof, error::Error> {
        let mut pub_affine: Affine = self.public_key.into();
        let mut secret_key: Scalar = self.secret_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        assert!(pub_affine.is_valid_var());

        // On-chain compatible HASH_TO_CURVE_PREFIX
        let h = hash_to_curve_prefix(alpha, &pub_affine);

        // gamma = H * sk
        let gamma = ecmult(self.ctx_mul, &h, &secret_key);

        // k = random()
        // We need to make sure that k < GROUP_ORDER
        let mut k = Scalar::randomize();
        let mut retries = 0;
        while k.gte(&GROUP_ORDER) || k.is_zero() {
            if retries > MAX_RETRIES {
                return Err(error::Error::RetriesExceeded);
            }
            k = Scalar::randomize();
            retries += 1;
        }

        // Calculate k * G = u
        let kg = ecmult_gen(self.ctx_gen, &k);
        // U = c * pk + s * G
        // u_witness = ecrecover(c * pk + s * G)
        // this value equal to address(keccak256(U))
        // It's a gas optimization for EVM
        // https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384
        let u_witness = calculate_witness_address(&kg);

        // Calculate k * H = v
        let kh = ecmult(self.ctx_mul, &h, &k);

        // c = ECVRF_hash_points_prefix(H, pk, gamma, u_witness, k * H)
        let c = hash_points_prefix(&h, &pub_affine, &gamma, &u_witness, &kh);

        // s = (k - c * sk)
        // Based on Schnorr signature
        let mut neg_c = c;
        neg_c.cond_neg_assign(1.into());
        let s = k + neg_c * secret_key;
        secret_key.clear();

        // Gamma witness
        // witness_gamma = gamma * c
        let witness_gamma = ecmult(self.ctx_mul, &gamma, &c);

        // Hash witness
        // witness_hash = h * s
        let witness_hash = ecmult(self.ctx_mul, &h, &s);

        // V = witness_gamma + witness_hash
        //   = c * gamma + s * H
        //   = c * (sk * H) + (k - c * sk) * H
        //   = k * H
        let v = projective_ec_add(&witness_gamma, &witness_hash);

        // Inverse do not guarantee that z is normalized
        // We need to normalize it after we done the inverse
        let mut inverse_z = v.z.inv();
        inverse_z.normalize();

        Ok(ECVRFContractProof {
            pk: self.public_key,
            gamma,
            c,
            s,
            y: Scalar::from_bytes(&gamma.keccak256()),
            alpha: *alpha,
            witness_address: Scalar::from_bytes(&u_witness),
            witness_gamma,
            witness_hash,
            inverse_z,
        })
    }

    /// Ordinary prover
    pub fn prove(&self, alpha: &Scalar) -> Result<ECVRFProof, error::Error> {
        let mut pub_affine: Affine = self.public_key.into();
        let mut secret_key: Scalar = self.secret_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        // Hash to a point on curve
        let h = hash_to_curve(alpha, Some(&pub_affine));

        // gamma = H * secret_key
        let gamma = ecmult(self.ctx_mul, &h, &secret_key);

        // k = random()
        // We need to make sure that k < GROUP_ORDER
        let mut k = Scalar::randomize();
        let mut retries = 0;
        while k.gte(&GROUP_ORDER) || k.is_zero() {
            if retries > MAX_RETRIES {
                return Err(error::Error::RetriesExceeded);
            }
            k = Scalar::randomize();
            retries += 1;
        }

        // Calculate k * G <=> u
        let kg = ecmult_gen(self.ctx_gen, &k);

        // Calculate k * H <=> v
        let kh = ecmult(self.ctx_mul, &h, &k);

        // c = ECVRF_hash_points(G, H, public_key, gamma, k * G, k * H)
        let c = hash_points(&AFFINE_G, &h, &pub_affine, &gamma, &kg, &kh);

        // s = (k - c * secret_key) mod p
        let mut neg_c = c;
        neg_c.cond_neg_assign(1.into());
        let s = k + neg_c * secret_key;
        secret_key.clear();

        // y = keccak256(gama.encode())
        let y = Scalar::from_bytes(&gamma.keccak256());

        Ok(ECVRFProof {
            gamma,
            c,
            s,
            y,
            pk: self.public_key,
        })
    }

    /// Ordinary verifier
    pub fn verify(&self, alpha: &Scalar, vrf_proof: &ECVRFProof) -> bool {
        let mut pub_affine: Affine = self.public_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        assert!(pub_affine.is_valid_var());
        assert!(vrf_proof.gamma.is_valid_var());

        // H = ECVRF_hash_to_curve(alpha, pk)
        let h = hash_to_curve(alpha, Some(&pub_affine));
        let mut jh = Jacobian::default();
        jh.set_ge(&h);

        // U = c * pk + s * G
        //   = c * sk * G + (k - c * sk) * G
        //   = k * G
        let mut u = Jacobian::default();
        let pub_jacobian = Jacobian::from_ge(&pub_affine);
        self.ctx_mul
            .ecmult(&mut u, &pub_jacobian, &vrf_proof.c, &vrf_proof.s);

        // Gamma witness
        let witness_gamma = ecmult(self.ctx_mul, &vrf_proof.gamma, &vrf_proof.c);
        // Hash witness
        let witness_hash = ecmult(self.ctx_mul, &h, &vrf_proof.s);

        // V = c * gamma + s * H = witness_gamma + witness_hash
        //   = c * sk * H + (k - c * sk) * H
        //   = k *. H
        let v = Jacobian::from_ge(&witness_gamma).add_ge(&witness_hash);

        // c_prime = ECVRF_hash_points(G, H, pk, gamma, U, V)
        let computed_c = hash_points(
            &AFFINE_G,
            &h,
            &pub_affine,
            &vrf_proof.gamma,
            &Affine::from_jacobian(&u),
            &Affine::from_jacobian(&v),
        );

        // y = keccak256(gama.encode())
        let computed_y = Scalar::from_bytes(&vrf_proof.gamma.keccak256());

        // computed values should equal to the real one
        computed_c.eq(&vrf_proof.c) && computed_y.eq(&vrf_proof.y)
    }
}

#[cfg(test)]
mod tests {
    use crate::{extends::ScalarExtend, ECVRF};
    use libsecp256k1::{curve::Scalar, SecretKey};
    use rand::thread_rng;

    #[test]
    fn we_should_able_to_prove_and_verify() {
        let mut r = thread_rng();
        let secret_key = SecretKey::random(&mut r);

        // Create new instance of ECVRF
        let ecvrf = ECVRF::new(secret_key);

        // Random an alpha value
        let alpha = Scalar::randomize();

        //Prove
        let r1 = ecvrf.prove(&alpha);

        // Verify
        let r2 = ecvrf.verify(&alpha, &r1.expect("Can not prove the randomness"));

        assert!(r2);
    }
}
