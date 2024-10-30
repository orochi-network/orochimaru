use crate::extends::AffineExtend;
use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar},
    PublicKey,
};
use rand::{thread_rng, RngCore};

/// Field size 2^256 - 0x1000003D1
/// [FIELD_SIZE](crate::helper::FIELD_SIZE) = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
pub const FIELD_SIZE: Scalar = Scalar([
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
]);

/// Group order
/// [GROUP_ORDER](crate::helper::GROUP_ORDER) = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const GROUP_ORDER: Scalar = Scalar([
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
]);

/// Projective sub, cost optimization for EVM
pub fn projective_sub(a: &Affine, b: &Affine) -> Affine {
    let mut x = b.y * a.x + a.y * b.x.neg(1);
    let mut y = a.y * b.y;
    x.normalize();
    y.normalize();
    Affine::new(x, y)
}

/// Projective mul, cost optimization of EVM
pub fn projective_mul(a: &Affine, b: &Affine) -> Affine {
    let mut x = a.x * b.x;
    let mut y = a.y * b.y;
    x.normalize();
    y.normalize();
    Affine::new(x, y)
}

/// Projective EC add
pub fn projective_ec_add(a: &Affine, b: &Affine) -> Jacobian {
    let mut r = Jacobian::default();
    let mut l = Affine::default();
    let (z1, z2) = (Field::from_int(1), Field::from_int(1));

    l.set_xy(&(b.y + a.y.neg(1)), &(b.x + a.x.neg(1)));

    let s1 = projective_mul(&l, &l);
    let s1 = projective_sub(&s1, &Affine::compose(&a.x, &z1));
    let s1 = projective_sub(&s1, &Affine::compose(&b.x, &z2));

    let s2 = projective_sub(&Affine::compose(&a.x, &z1), &s1);
    let s2 = projective_mul(&s2, &l);
    let s2 = projective_sub(&s2, &Affine::compose(&a.y, &z1));

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

/// Perform multiplication between a point and a scalar: a * P
pub fn ecmult(context: &ECMultContext, a: &Affine, na: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    context.ecmult(&mut rj, &Jacobian::from_ge(a), na, &Scalar::from_int(0));
    Affine::from_jacobian(&rj)
}

/// Perform multiplication between a value and G: a * G
pub fn ecmult_gen(context: &ECMultGenContext, ng: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    context.ecmult_gen(&mut rj, ng);
    Affine::from_jacobian(&rj)
}

/// Calculate witness address from a Affine
pub fn calculate_witness_address(witness: &Affine) -> [u8; 20] {
    let mut result = [0u8; 20];
    result.copy_from_slice(&witness.keccak256()[12..32]);
    result
}

/// Has a Public Key and return a Ethereum address
pub fn get_address(pub_key: &PublicKey) -> [u8; 20] {
    let mut affine_pub: Affine = (*pub_key).into();
    affine_pub.x.normalize();
    affine_pub.y.normalize();
    calculate_witness_address(&affine_pub)
}

/// Random bytes array
pub fn random_bytes(buf: &mut [u8]) {
    let mut rng = thread_rng();
    rng.fill_bytes(buf);
}
