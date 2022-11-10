use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar},
    util::{FULL_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE},
    PublicKey, SecretKey,
};
use rand::{thread_rng, RngCore};
use tiny_keccak::{Hasher, Keccak};

pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub struct RawKeyPair {
    pub public_key: [u8; FULL_PUBLIC_KEY_SIZE],
    pub secret_key: [u8; SECRET_KEY_SIZE],
}

// Perform multiplication between a point and a value: a*P
pub fn ecmult(context: &ECMultContext, a: &Affine, na: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    let temp_aj = Jacobian::from_ge(a);
    context.ecmult(&mut rj, &temp_aj, na, &Scalar::from_int(0));
    let mut ra = Affine::from_gej(&rj);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

// Perform multiplication between a value and G: a*G
pub fn ecmult_gen(context: &ECMultGenContext, ng: &Scalar) -> Affine {
    let mut r = Jacobian::default();
    context.ecmult_gen(&mut r, &ng);
    let mut ra = Affine::from_gej(&r);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

// Quick transform a Jacobian to Affine and also normalize it
pub fn jacobian_to_affine(j: &Jacobian) -> Affine {
    let mut ra = Affine::from_gej(j);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

// Keccak a point
pub fn keccak256_affine(a: &Affine) -> Scalar {
    let mut r = Scalar::default();
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(a.x.b32().as_ref());
    hasher.update(a.y.b32().as_ref());
    hasher.finalize(&mut output);
    r.set_b32(&output).unwrap_u8();
    r
}

// Random Scalar
pub fn randomize() -> Scalar {
    let mut rng = thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let mut result = Scalar::default();
    result.set_b32(&random_bytes).unwrap_u8();
    result
}

// Generate a new key pair
pub fn generate_keypair() -> KeyPair {
    let mut rng = thread_rng();
    let secret_key = SecretKey::random(&mut rng);
    let public_key = PublicKey::from_secret_key(&secret_key);
    KeyPair {
        public_key,
        secret_key,
    }
}

pub fn generate_raw_keypair() -> RawKeyPair {
    let mut rng = thread_rng();
    let secret = SecretKey::random(&mut rng);
    let secret_key = secret.serialize();
    let public_key = PublicKey::from_secret_key(&secret).serialize();
    RawKeyPair {
        public_key,
        secret_key,
    }
}

// Random bytes
pub fn random_bytes(buf: &mut [u8]) {
    let mut rng = thread_rng();
    rng.fill_bytes(buf);
}

// Normalize a Scalar
pub fn normalize_scalar(s: &Scalar) -> Scalar {
    let mut f = Field::default();
    let mut r = Scalar::default();
    // @TODO: we should have better approach to handle this
    if !f.set_b32(&s.b32()) {
        panic!("Unable to set field with given bytes array");
    }
    f.normalize();
    r.set_b32(&f.b32()).unwrap_u8();
    r
}
