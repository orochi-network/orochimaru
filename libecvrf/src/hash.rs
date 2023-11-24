use crate::{
    extends::{AffineExtend, ScalarExtend},
    helper::FIELD_SIZE,
};
use libsecp256k1::{
    curve::{Affine, Field, Jacobian, Scalar},
    ECMULT_GEN_CONTEXT,
};
use tiny_keccak::{Hasher, Keccak};

/// Try to generate a point on the curve based on hashes
pub fn new_candidate_point(b: &[u8]) -> Affine {
    // X is a digest of field
    let mut x = field_hash(b);
    // Y is a coordinate point, corresponding to x
    let (mut y, _) = y_squared(&x).sqrt();
    x.normalize();
    y.normalize();

    if y.is_odd() {
        y = y.neg(1);
        y.normalize();
    }
    Affine::new(x, y)
}

/// Y squared, it was calculate by evaluate X
pub fn y_squared(x: &Field) -> Field {
    let mut t = *x;
    // y^2 = x^3 + 7
    t = t * t * t + Field::from_int(7);
    t.normalize();
    t
}

/// Check point is on curve or not
pub fn is_on_curve(point: &Affine) -> bool {
    y_squared(&point.x) == point.y * point.y
}

/// Hash to curve with prefix
/// HASH_TO_CURVE_HASH_PREFIX = 1
pub fn hash_to_curve_prefix(alpha: &Scalar, pk: &Affine) -> Affine {
    let mut tpk = *pk;
    tpk.x.normalize();
    tpk.y.normalize();
    let packed = [
        // HASH_TO_CURVE_HASH_PREFIX = 1
        Field::from_int(1).b32().to_vec(),
        // pk
        tpk.x.b32().to_vec(),
        tpk.y.b32().to_vec(),
        // seed
        alpha.b32().to_vec(),
    ]
    .concat();
    let mut rv = new_candidate_point(&packed);
    while !is_on_curve(&rv) {
        rv = new_candidate_point(rv.x.b32().as_ref());
    }
    rv
}

/// Hash bytes array to a field
pub fn field_hash(b: &[u8]) -> Field {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b);
    hasher.finalize(&mut output);
    let mut s = Scalar::from_bytes(&output);
    if s.gte(&FIELD_SIZE) {
        let mut hasher = Keccak::v256();
        hasher.update(&output);
        hasher.finalize(&mut output);
        assert!(bool::from(s.set_b32(&output)), "Unable to set field");
    }
    let mut f = Field::default();
    if !f.set_b32(&s.b32()) {
        f.normalize();
    }
    f
}

/// Hash point to Scalar
pub fn hash_points(
    g: &Affine,
    h: &Affine,
    pk: &Affine,
    gamma: &Affine,
    kg: &Affine,
    kh: &Affine,
) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let all_points = [g, h, pk, gamma, kg, kh];
    for point in all_points {
        hasher.update(point.x.b32().as_ref());
        hasher.update(point.y.b32().as_ref());
    }
    hasher.finalize(&mut output);
    Scalar::from_bytes(&output)
}

/// Hash points with prefix
/// SCALAR_FROM_CURVE_POINTS_HASH_PREFIX = 2
pub fn hash_points_prefix(
    hash: &Affine,
    pk: &Affine,
    gamma: &Affine,
    u_witness: &[u8; 20],
    v: &Affine,
) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let all_points = [hash, pk, gamma, v];
    // SCALAR_FROM_CURVE_POINTS_HASH_PREFIX = 2
    hasher.update(Scalar::from_int(2).b32().as_ref());
    for point in all_points {
        hasher.update(point.x.b32().as_ref());
        hasher.update(point.y.b32().as_ref());
    }
    hasher.update(u_witness);
    hasher.finalize(&mut output);
    Scalar::from_bytes(&output)
}

/// Hash to curve
pub fn hash_to_curve(alpha: &Scalar, y: Option<&Affine>) -> Affine {
    let mut r = Jacobian::default();
    ECMULT_GEN_CONTEXT.ecmult_gen(&mut r, alpha);
    match y {
        Some(v) => {
            r = r.add_ge(v);
            r
        }
        None => r,
    };
    Affine::from_jacobian(&r)
}

#[cfg(test)]
mod tests {
    use crate::{
        extends::ScalarExtend,
        hash::{is_on_curve, new_candidate_point},
        helper::random_bytes,
    };
    use libsecp256k1::curve::Scalar;

    #[test]
    fn point_must_be_on_curve() {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf);
        let mut rv = new_candidate_point(buf.as_ref());
        while !is_on_curve(&rv) {
            rv = new_candidate_point(&rv.x.b32());
        }
        assert!(is_on_curve(&rv));
    }

    #[test]
    fn test_scalar_is_gte() {
        let data_set = [
            Scalar([0, 1, 1, 1, 1, 1, 1, 0]),
            Scalar([1, 0, 0, 0, 0, 0, 0, 1]),
            Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
            Scalar([1, 0, 0, 0, 0, 0, 1, 0]),
            Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
            Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
        ];
        let require_output = [
            true, false, false, true, false, false, true, true, false, true, false, false, true,
            true, true, true, true, true, false, false, false, true, false, false, true, true,
            true, true, true, true, true, true, true, true, true, true,
        ];
        for x in 0..data_set.len() {
            for y in 0..data_set.len() {
                assert!(
                    data_set[x].gte(&data_set[y]) == require_output[x * data_set.len() + y],
                    "scalar_is_gte() is broken"
                );
            }
        }
    }

    #[test]
    fn test_scalar_is_gt() {
        let data_set = [
            Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
            Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
            Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
            Scalar([0, 0, 0, 0, 0, 0, 0, 0]),
            Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
            Scalar([0, 0, 0, 0, 0, 0, 0, 2]),
            Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
            Scalar([0, 0, 0, 0, 0, 1, 1, 1]),
            Scalar([0, 1, 1, 1, 1, 1, 1, 1]),
            Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
        ];
        let require_output = [
            false, false, false, true, false, false, false, false, false, false, false, false,
            false, true, false, false, false, false, false, false, true, true, false, true, false,
            false, false, true, true, false, false, false, false, false, false, false, false,
            false, false, false, true, true, false, true, false, false, false, true, true, false,
            true, true, true, true, true, false, true, true, true, true, true, true, false, true,
            false, false, false, true, true, false, true, true, false, true, false, false, false,
            false, false, false, true, true, false, true, false, false, false, true, false, false,
            true, true, false, true, false, false, false, true, true, false,
        ];

        for x in 0..data_set.len() {
            for y in 0..data_set.len() {
                assert!(
                    data_set[x].gt(&data_set[y]) == require_output[x * data_set.len() + y],
                    "scalar_is_gt() is broken"
                );
            }
        }
    }
}
