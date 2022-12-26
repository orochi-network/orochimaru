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

// Field size 2^256 - 0x1000003D1
// FIELD_SIZE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
pub const FIELD_FIELD_SIZE: Field = Field::new(0, 0, 0, 0, 0, 0, 0, 0);

// Compose Affine for its coordinate X,Y
pub fn affine_composer(x: &Field, y: &Field) -> Affine {
    let mut r = Affine::default();
    r.set_xy(x, y);
    r.x.normalize();
    r.y.normalize();
    r
}

// Projective sub, cost optimization for EVM
pub fn projective_sub(a: &Affine, b: &Affine) -> Affine {
    let mut c = Affine::default();
    c.x = b.y * a.x + a.y * b.x.neg(1);
    c.y = a.y * b.y;
    c.x.normalize();
    c.y.normalize();
    c
}

// Projective mul, cost optimization of EVM
pub fn projective_mul(a: &Affine, b: &Affine) -> Affine {
    let mut c = Affine::default();
    c.x = a.x * b.x;
    c.y = a.y * b.y;
    c.x.normalize();
    c.y.normalize();
    c
}

// Projective EC add
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

// Quick transform a Jacobian to Affine and also normalize it
pub fn jacobian_to_affine(j: &Jacobian) -> Affine {
    let mut ra = Affine::from_gej(j);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

// Perform multiplication between a point and a scalar: a * P
pub fn ecmult(context: &ECMultContext, a: &Affine, na: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    context.ecmult(&mut rj, &Jacobian::from_ge(a), na, &Scalar::from_int(0));
    jacobian_to_affine(&rj)
}

// Perform multiplication between a value and G: a * G
pub fn ecmult_gen(context: &ECMultGenContext, ng: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    context.ecmult_gen(&mut rj, &ng);
    jacobian_to_affine(&rj)
}

// Check point is on curve or not
pub fn is_on_curve(point: &Affine) -> bool {
    y_squared(&point.x) == point.y * point.y
}

pub fn keccak256_affine(a: &Affine) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(a.x.b32().as_ref());
    hasher.update(a.y.b32().as_ref());
    hasher.finalize(&mut output);
    output
}

// Keccak a point to scalar
pub fn keccak256_affine_scalar(a: &Affine) -> Scalar {
    let mut r = Scalar::default();
    r.set_b32(&keccak256_affine(&a)).unwrap_u8();
    r
}

// Keccak a vector to scalar
pub fn keccak256_vec_scalar(a: &Vec<u8>) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(a.as_slice());
    hasher.finalize(&mut output);
    let mut r = Scalar::default();
    r.set_b32(&output).unwrap_u8();
    r
}

// Calculate witness address from a point
pub fn calculate_witness_address(witness: &Affine) -> [u8; 20] {
    keccak256_affine(witness)[12..32].try_into().unwrap()
}

// Convert address to Scalar type
pub fn address_to_scalar(witness_address: &[u8; 20]) -> Scalar {
    let mut temp_bytes = [0u8; 32];
    let mut scalar_address = Scalar::default();
    for i in 0..20 {
        temp_bytes[12 + i] = witness_address[i];
    }
    scalar_address.set_b32(&temp_bytes).unwrap_u8();
    scalar_address
}

// Has a Public Key and return a Ethereum address
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

// Hash bytes array to a field
pub fn field_hash(b: &Vec<u8>) -> Field {
    let mut s = Scalar::default();
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b);
    hasher.finalize(&mut output);
    s.set_b32(&output).unwrap_u8();
    if scalar_is_gte(&s, &FIELD_SIZE) {
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
        if a.0[i] < b.0[i] {
            return false;
        }
        if a.0[i] > b.0[i] {
            return true;
        }
    }
    false
}

// Return true if a >= b

pub fn scalar_is_gte(a: &Scalar, b: &Scalar) -> bool {
    for i in (0..a.0.len()).rev() {
        if a.0[i] < b.0[i] {
            return false;
        }
        if a.0[i] > b.0[i] {
            return true;
        }
    }
    true
}

// Try to generate a point on the curve based on hashes
pub fn new_candidate_point(b: &Vec<u8>) -> Affine {
    let mut r = Affine::default();
    // X is a digest of field
    r.x = field_hash(b);
    // Y is a coordinate point, corresponding to x
    (r.y, _) = y_squared(&r.x).sqrt();
    r.x.normalize();
    r.y.normalize();

    if r.y.is_odd() {
        r.y = r.y.neg(1);
        r.y.normalize();
    }
    r
}

// Y squared, it was calculate by evaluate X
pub fn y_squared(x: &Field) -> Field {
    let mut t = x.clone();
    // y^2 = x^3 + 7
    t = t * t * t + Field::from_int(7);
    t.normalize();
    t
}

// Random bytes array
pub fn random_bytes(buf: &mut [u8]) {
    let mut rng = thread_rng();
    rng.fill_bytes(buf);
}

// Random Scalar
pub fn randomize() -> Scalar {
    let mut result = Scalar::default();
    let mut buf = [0u8; 32];
    random_bytes(&mut buf);
    result.set_b32(&buf).unwrap_u8();
    result
}

// Generate a new libsecp256k1 key pair
pub fn generate_keypair() -> KeyPair {
    let mut rng = thread_rng();
    let secret_key = SecretKey::random(&mut rng);
    let public_key = PublicKey::from_secret_key(&secret_key);
    KeyPair {
        public_key,
        secret_key,
    }
}

// Generate raw key pair in bytes array
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

#[cfg(test)]
mod tests {
    use crate::{helper::randomize, ECVRF};
    use libsecp256k1::{curve::{Affine,Scalar}, SecretKey};

    use super::{is_on_curve, new_candidate_point, random_bytes};

    #[test]
    fn point_must_be_on_curve() {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf);
        let mut rv = new_candidate_point(buf.to_vec().as_ref());
        while !is_on_curve(&rv) {
            rv = new_candidate_point(&rv.x.b32().to_vec());
        }
        assert!(is_on_curve(&rv));
    }


    fn test_gt_and_gte(){
        //Testcase 1
       let b=
            scalar_is_gte(
                &Scalar([
                    0x00000000, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
                    0x00000001, 0x00000000,
                ]),
                &Scalar([
                    0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                    0x00000000, 0x00000001,
                ])
            );
            assert!(b==false);
    //Testcase 2
    let b=
            scalar_is_gte(
                &Scalar([
                    0x00000000,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000000,0x00000001
                ]),
                &Scalar([
                    0x00000001, 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000001,0x00000000
                ])
            );
            assert!(b==true);
    //Testcase 3
    let b=
            scalar_is_gte(
                &Scalar([
                    0x00000000,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000000,0x00000001
                ]),
                &Scalar([
                    0x00000000,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000000,0x00000001
                ])
            );
            assert!(b==true);
    //Testcase 4
    let b=
            scalar_is_gt(
                &Scalar([
                    0x00000000,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000000,0x00000001
                ]),
                &Scalar([
                    0x00000000,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000000,0x00000001
                ])
            );
            assert!(b==false);
    // Testcase 5
    let b=
    scalar_is_gt(
        &Scalar([
            0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001
        ]),
        &Scalar([
            0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000
        ])
    );
    assert!(b==true);
    // Testcase 6
    let b=
    scalar_is_gt(
        &Scalar([
            0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001
        ]),
        &Scalar([
            0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000002
        ])
    );
    assert!(b==false);
    // Testcase 7
    let b=
    scalar_is_gt(
        &Scalar([
            0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001
        ]),
        &Scalar([
            0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000001,0x00000001,0x00000001
        ])
    );
    assert!(b==true);


    // Testcase 8
    let b=
    scalar_is_gt(
        &Scalar([
            0x00000000,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001
        ]),
        &Scalar([
            0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001
        ])
    );
    assert!(b==false);
    }
}
