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

const RAW_FIELD_SIZE: [u32; 8] = [
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
];

pub const FIELD_SIZE: Scalar = Scalar(RAW_FIELD_SIZE);

pub fn affine_composer(x: &Field, y: &Field) -> Affine {
    let mut r = Affine::default();
    r.set_xy(x, y);
    r.x.normalize();
    r.y.normalize();
    r
}

pub fn projective_sub(a: &Affine, b: &Affine) -> Affine {
    let mut c = Affine::default();
    c.x = b.y * a.x + a.y * b.x.neg(1);
    c.y = a.y * b.y;
    c.x.normalize();
    c.y.normalize();
    c
}

pub fn projective_mul(a: &Affine, b: &Affine) -> Affine {
    let mut c = Affine::default();
    c.x = a.x * b.x;
    c.y = a.y * b.y;
    c.x.normalize();
    c.y.normalize();
    c
}

pub fn projective_ec_add(a: &Affine, b: &Affine) -> Jacobian {
    let mut r = Jacobian::default();
    let mut l = Affine::default();
    let (z1, z2) = (Field::from_int(1), Field::from_int(1));

    l.set_xy(&(b.y + a.y.neg(1)), &(b.x + a.x.neg(1)));

    let s1 = projective_mul(&l, &l);
    let s1 = projective_sub(&s1, &affine_composer(&a.x, &z1));
    let s1 = projective_sub(&s1, &affine_composer(&b.x, &z2));

    let s2 = projective_sub(&affine_composer(&a.x, &z1), &s1);
    let s2 = projective_mul(&s2, &l);
    let s2 = projective_sub(&s2, &affine_composer(&a.y, &z1));

    if s1.y != s2.y {
        r.x = s1.x * s2.y;
        r.y = s2.x * s1.y;
        r.z = s1.y * s2.y;
    } else {
        r.x = s1.x;
        r.y = s2.x;
        r.z = s1.y;
    }

    r.x.normalize();
    r.y.normalize();
    r.z.normalize();
    r
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

pub fn is_on_curve(point: &Affine) -> bool {
    y_squared(&point.x) == point.y * point.y
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

pub fn calculate_witness_address(witness: &Affine) -> [u8; 20] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(witness.x.b32().as_ref());
    hasher.update(witness.y.b32().as_ref());
    hasher.finalize(&mut output);
    output[12..32].try_into().unwrap()
}

pub fn address_to_scalar(witness_address: &[u8; 20]) -> Scalar {
    let mut temp_bytes = [0u8; 32];
    let mut scalar_address = Scalar::default();
    for i in 0..20 {
        temp_bytes[12 + i] = witness_address[i];
    }
    scalar_address.set_b32(&temp_bytes).unwrap_u8();
    scalar_address
}

pub fn get_address(pub_key: PublicKey) -> [u8; 20] {
    let mut affine_pub: Affine = pub_key.into();
    affine_pub.x.normalize();
    affine_pub.y.normalize();
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(affine_pub.x.b32().as_ref());
    hasher.update(affine_pub.y.b32().as_ref());
    hasher.finalize(&mut output);
    output[12..32].try_into().unwrap()
}

pub fn get_scalar_address(pub_key: PublicKey) -> Scalar {
    let bytes = get_address(pub_key);
    let mut temp_bytes = [0u8; 32];
    let mut scalar_address = Scalar::default();
    for i in 0..20 {
        temp_bytes[12 + i] = bytes[i];
    }
    scalar_address.set_b32(&temp_bytes).unwrap_u8();
    scalar_address
}

pub fn field_hash(b: &Vec<u8>) -> Field {
    let mut s = Scalar::default();
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b);
    hasher.finalize(&mut output);
    s.set_b32(&output).unwrap_u8();
    if scalar_is_gt(&s, &FIELD_SIZE) {
        let mut hasher = Keccak::v256();
        hasher.update(&output);
        hasher.finalize(&mut output);
        s.set_b32(&output).unwrap_u8();
    }
    let mut f = Field::default();
    if !f.set_b32(&s.b32()) {
        f.normalize();
    }
    f
}

// Return true if a > b
pub fn scalar_is_gt(a: &Scalar, b: &Scalar) -> bool {
    for i in (0..a.0.len()).rev() {
        if a.0[i] > b.0[i] {
            return true;
        }
    }
    false
}

// Return true if a >= b
pub fn scalar_is_gte(a: &Scalar, b: &Scalar) -> bool {
    for i in (0..a.0.len()).rev() {
        if a.0[i] >= b.0[i] {
            return true;
        }
    }
    false
}

pub fn new_candidate_point(b: &Vec<u8>) -> Affine {
    let mut x = field_hash(b);
    let mut y = y_squared(&x);
    let mut field_size = Field::default();
    if !field_size.set_b32(&FIELD_SIZE.b32()) {
        field_size.normalize();
    }
    x.normalize();
    (y, _) = y.sqrt();
    y.normalize();

    if y.is_odd() {
        // Negative of y
        let mut invert_y = y.clone();
        invert_y = invert_y.neg(1);
        invert_y.normalize();
        // y = FIELD_SIZE - y
        y = invert_y + field_size;
        y.normalize();
    }

    let mut r = Affine::default();
    r.set_xy(&x, &y);
    r
}

pub fn y_squared(x: &Field) -> Field {
    let mut t = x.clone();
    // y^2 = x^3 + 7
    t = t * t * t + Field::from_int(7);
    t.normalize();
    t
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
