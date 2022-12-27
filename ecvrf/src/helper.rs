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

// Field size 2^256 - 0x1000003D1
// FIELD_SIZE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
pub const FIELD_SIZE: Scalar = Scalar([
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
]);

// GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const GROUP_ORDER: Scalar = Scalar([
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
]);

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
    use crate::ECVRF;
    use libsecp256k1::{curve::{Scalar,Affine,Jacobian,Field}, SecretKey};

    use super::{
        is_on_curve, new_candidate_point, random_bytes, randomize, scalar_is_gt, scalar_is_gte,
    };

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
                    scalar_is_gte(&data_set[x], &data_set[y])
                        == require_output[x * data_set.len() + y],
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
                    scalar_is_gt(&data_set[x], &data_set[y])
                        == require_output[x * data_set.len() + y],
                    "scalar_is_gt() is broken"
                );
            }
        }
    }


    #[test]
    // The results below have been tested on chainlink.
    fn test_projective_ec_add(){
        //Check the correctness of the projective_ec_add function
       let P_x=[
        Field::new_raw(1014095, 27245485, 18079781, 62818885, 6005449, 27754920, 47166199, 49620396, 20482281, 64453196),
        Field::new_raw(2881937, 30269476, 30651653, 27828758, 49430413, 38968291, 62159435, 14563297, 3762092, 64301321),
        Field::new_raw(888935, 44876924, 33376525, 46322353, 23014199, 43534704, 2075997, 58613759, 13276206, 38459183),
        Field::new_raw(1173538, 5251979, 45514189, 47172267, 41083573, 64264174, 57207202, 37126255, 20634493, 18626283),
        Field::new_raw(34978, 8986890, 32328974, 6429458, 62735188, 6404883, 65609615, 56258350, 14825711, 27493980)
       ];

      
       

       let P_y=[
        Field::new_raw(3323709, 63880799, 34911351, 22193901, 58305475, 42647907, 64791389, 9908645, 34832096, 24942443),
        Field::new_raw(3681752, 46030946, 56815721, 9970617, 44706522, 58420823, 4363185, 7983735, 763546, 58977104),
        Field::new_raw(1626124, 10498509, 50083977, 34434173, 29951089, 28916303, 774447, 31747696, 38256805, 32493680),
        Field::new_raw(1482774, 28662690, 19892534, 7635144, 21201279, 55891098, 48982497, 25061615, 55177987, 56318785),
        Field::new_raw(1962413, 32872974, 54025012, 31576763, 52170737, 5067518, 34877004, 58106407, 31099250, 49435711)
       ];
       
       
       let Q_x=[
        Field::new_raw( 3949615, 66779817, 1606560, 47410390, 831760, 1795286, 36595269, 30921352, 48240622, 31121077),
        Field::new_raw(466159, 4706190, 56774435, 50585987, 56106904, 4236017, 49124608, 24621076, 37495853, 20301811),
        Field::new_raw(3865535, 15171696, 3241387, 42670770, 59787283, 45319471, 30668869, 17429567, 66937484, 58643956),
        Field::new_raw(3965362, 8238738, 33125405, 28588179, 11796129, 21871629, 24563963, 10945136, 59314097, 36909114),
        Field::new_raw(2937111, 50241608, 8444056, 52466045, 22141634, 60295819, 54344661, 56167125, 55470749, 49532653)
       ];

       let Q_y=[
        Field::new_raw(2142565, 27820731, 60992473, 42219931, 62769828, 14814230, 7831328, 45332626, 47127755, 36936398),
        Field::new_raw(1749105, 43673108, 52090356, 36082059, 30968079, 37767043, 52130192, 58004526, 32090187, 10356912),
        Field::new_raw(3016472, 23348998, 40196548, 39679416, 64455134, 13771147, 19775228, 5711618, 26240227, 36404485),
        Field::new_raw(656600, 11568354, 22113171, 57657914, 30818497, 5831077, 34556057, 44295645, 59443515, 55588429),
        Field::new_raw(1167556, 27341782, 57918609, 58030667, 18863569, 48751500, 61601032, 34671145, 26108266, 2677945)
       ];

        let R_x=[
            Field::new_raw(1838677, 7158945, 56087361, 27064659, 42315756, 49776020, 38075574, 33867422, 49809746, 14281852),
            Field::new_raw(2462413, 22740053, 33150857, 8412637, 21642197, 4835937, 32718487, 50201252, 12415716, 18472476),
            Field::new_raw(2960637, 32560841, 57171124, 64725753, 47879677, 1694297, 3505259, 13397197, 15134383, 37571661),
            Field::new_raw(904856, 57226798, 41399843, 40377572, 40886400, 57915880, 62676632, 50889666, 60821450, 29856311),
            Field::new_raw(784655, 44258734, 27600880, 66250229, 57875392, 24729073, 38070598, 2602594, 6003575, 24191994)
        ];
        let R_y=[
            Field::new_raw(76599, 57880985, 16656958, 5837499, 9722279, 28603191, 42014985, 37913965, 41355961, 30599916),
            Field::new_raw(793801, 55065223, 41505364, 35191912, 14566757, 65865732, 39564011, 28065904, 55682892, 39222388),
            Field::new_raw(165206, 3315826, 48468169, 17069393, 56978389, 39387409, 52681255, 58481794, 40551398, 61009165),
            Field::new_raw(1825482, 27778166, 30683534, 28169350, 22418579, 62384284, 1656908, 32702240, 29990198, 64177265),
            Field::new_raw(3201736, 19484849, 61910818, 23829149, 16109573, 3621671, 62931831, 12545403, 50031917, 15180079)
        ];
        let R_z=[
            Field::new_raw(2963800, 35258506, 56555144, 48221335, 37275811, 47111649, 30564697, 62163006, 5607768, 33627847),
            Field::new_raw(3621819, 56142224, 6497026, 19513487, 31005699, 64382370, 61973006, 31282047, 39692822, 38703415),
            Field::new_raw(936954, 42542377, 52907648, 55981871, 33969320, 44110150, 10742065, 33193877, 35994484, 58271547),
            Field::new_raw(3474970, 13596286, 53644147, 59861713, 20092981, 15712353, 35065860, 41924848, 58811872, 51889383),
            Field::new_raw(3745138, 41183687, 19090533, 45391971, 36511456, 51087497, 33703536, 23019368, 26518385, 19502344)
        ];

        let mut P=Affine::default();
        let mut Q=Affine::default();
        let mut R=Jacobian::default();

        for i in 0..P_x.len()
        {
            P.x=P_x[i];
            P.y=P_y[i];

            Q.x=Q_x[i];
            Q.y=Q_y[i];

            R=projective_ec_add(&P, &Q);
            assert!(R.x==R_x[i]);
            assert!(R.y==R_y[i]);
            assert!(R.z==R_z[i]);
        
        };

}
}
