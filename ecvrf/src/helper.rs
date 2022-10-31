use libsecp256k1::curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar};
use rand::{thread_rng, RngCore};
use tiny_keccak::{Hasher, Keccak};

pub fn ecmult(context: &ECMultContext, a: &Affine, na: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    let temp_aj = Jacobian::from_ge(a);
    context.ecmult(&mut rj, &temp_aj, na, &Scalar::from_int(0));
    let mut ra = Affine::from_gej(&rj);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

pub fn ecmult_gen(context: &ECMultGenContext, ng: &Scalar) -> Affine {
    let mut r = Jacobian::default();
    context.ecmult_gen(&mut r, &ng);
    let mut ra = Affine::from_gej(&r);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

pub fn jacobian_to_affine(j: &Jacobian) -> Affine {
    let mut ra = Affine::from_gej(j);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

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

pub fn randomize() -> Scalar {
    let mut rng = thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let mut result = Scalar::default();
    result.set_b32(&random_bytes).unwrap_u8();
    result
}

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
