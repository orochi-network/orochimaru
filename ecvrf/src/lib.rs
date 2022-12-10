use ecproof::ECVRFContractProof;
use helper::{address_to_scalar, calculate_witness_address, is_on_curve, new_candidate_point};
use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar, AFFINE_G},
    PublicKey, SecretKey, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT,
};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    ecproof::ECVRFProof,
    helper::{
        ecmult, ecmult_gen, jacobian_to_affine, keccak256_affine, normalize_scalar, projective_add,
        randomize,
    },
};

pub mod ecproof;
pub mod helper;
pub mod secp256k1 {
    pub use libsecp256k1::*;
}
pub mod random {
    pub use rand::thread_rng;
}

pub struct ECVRF<'a> {
    secret_key: SecretKey,
    public_key: PublicKey,
    ctx_mul: &'a ECMultContext,
    ctx_gen: &'a ECMultGenContext,
}

impl ECVRF<'_> {
    pub fn new(secret_key: SecretKey) -> Self {
        ECVRF {
            secret_key: secret_key,
            public_key: PublicKey::from_secret_key(&secret_key),
            ctx_gen: &ECMULT_GEN_CONTEXT,
            ctx_mul: &ECMULT_CONTEXT,
        }
    }

    pub fn hash_to_curve_prefix(&self, alpha: &Scalar, pk: &Affine) -> Affine {
        let mut tpk = pk.clone();
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
            rv = new_candidate_point(&[rv.y.b32().to_vec(), rv.y.b32().to_vec()].concat());
        }
        rv
    }

    pub fn hash_to_curve(&self, alpha: &Scalar, y: Option<&Affine>) -> Affine {
        let mut r = Jacobian::default();
        self.ctx_gen.ecmult_gen(&mut r, alpha);
        let mut p = Affine::default();
        match y {
            Some(v) => {
                r = r.add_ge(v);
                r
            }
            None => r,
        };
        p.set_gej(&r);
        p.x.normalize();
        p.y.normalize();
        p
    }

    // keccak256 cheaper on Ethereum
    pub fn hash_points(
        &self,
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
        let mut r = Scalar::default();
        r.set_b32(&output).unwrap_u8();
        r
    }

    // keccak256 cheaper on Ethereum
    // SCALAR_FROM_CURVE_POINTS_HASH_PREFIX = 2
    pub fn hash_points_prefix(
        &self,
        hash: &Affine,
        pk: &Affine,
        gamma: &Affine,
        u_witness: &[u8; 20],
        v: &Affine,
    ) -> Scalar {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        let all_points = [hash, pk, gamma, v];
        hasher.update(Scalar::from_int(2).b32().as_ref());
        for point in all_points {
            hasher.update(point.x.b32().as_ref());
            hasher.update(point.y.b32().as_ref());
        }
        hasher.update(u_witness);
        hasher.finalize(&mut output);
        let mut r = Scalar::default();
        r.set_b32(&output).unwrap_u8();
        r
    }

    pub fn prove_contract(self, alpha: &Scalar) -> ECVRFContractProof {
        let mut pub_affine: Affine = self.public_key.into();
        let mut secret_key: Scalar = self.secret_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        // Old approach H = ECVRF_hash_to_curve(alpha, public_key)
        // let h = self.hash_to_curve(alpha, Option::from(&pub_affine));
        // On-chain compatible HASH_TO_CURVE
        let h = self.hash_to_curve_prefix(alpha, &pub_affine);

        // gamma = H * secret_key
        let gamma = ecmult(self.ctx_mul, &h, &secret_key);

        // k = random()
        let k = randomize();

        // Calculate k * G = u
        let kg = ecmult_gen(self.ctx_gen, &k);
        let u_witness = calculate_witness_address(&kg);

        // Calculate k * H = v
        let kh = ecmult(self.ctx_mul, &h, &k);

        // c = ECVRF_hash_points(G, H, public_key, gamma, k * G, k * H)
        let c = self.hash_points_prefix(&h, &pub_affine, &gamma, &u_witness, &kh);

        // s = (k - c * secret_key) mod p
        let mut neg_c = c.clone();
        neg_c.cond_neg_assign(1.into());
        let s = normalize_scalar(&(k + neg_c * secret_key));
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
        let v = projective_add(&witness_gamma, &witness_hash);

        // Inverse do not guarantee that z is normalized
        // We need to normalize it after we done the inverse
        let mut inverse_z = v.z.inv();
        inverse_z.normalize();

        ECVRFContractProof {
            pk: self.public_key,
            gamma,
            c,
            s,
            y: keccak256_affine(&gamma),
            alpha: *alpha,
            witness_address: address_to_scalar(&u_witness),
            witness_gamma,
            witness_hash,
            inverse_z,
        }
    }

    pub fn prove(&self, alpha: &Scalar) -> ECVRFProof {
        let mut pub_affine: Affine = self.public_key.into();
        let mut secret_key: Scalar = self.secret_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        // Old approach H = ECVRF_hash_to_curve(alpha, public_key)
        // let h = self.hash_to_curve(alpha, Option::from(&pub_affine));
        // On-chain compatible HASH_TO_CURVE
        let h = self.hash_to_curve_prefix(alpha, &pub_affine);

        // gamma = H * secret_key
        let gamma = ecmult(self.ctx_mul, &h, &secret_key);

        // k = random()
        let k = randomize();

        // Calculate k * G <=> u
        // U = c * pk + s * G
        //   = c * sk * G + (k - c * sk) * G
        //   = k * G
        let kg = ecmult_gen(self.ctx_gen, &k);

        // Calculate k * H <=> v
        let kh = ecmult(self.ctx_mul, &h, &k);

        // c = ECVRF_hash_points(G, H, public_key, gamma, k * G, k * H)
        let c = self.hash_points(&AFFINE_G, &h, &pub_affine, &gamma, &kg, &kh);

        // s = (k - c * secret_key) mod p
        let mut neg_c = c.clone();
        neg_c.cond_neg_assign(1.into());
        let s = normalize_scalar(&(k + neg_c * secret_key));
        secret_key.clear();

        // y = keccak256(gama.encode())
        let y = keccak256_affine(&gamma);

        ECVRFProof::new(gamma, c, s, y, self.public_key)
    }

    pub fn verify(self, alpha: &Scalar, vrf_proof: &ECVRFProof) -> bool {
        let mut pub_affine: Affine = self.public_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        assert!(pub_affine.is_valid_var());
        assert!(vrf_proof.gamma.is_valid_var());

        // H = ECVRF_hash_to_curve(alpha, pk)
        // let h = self.hash_to_curve(alpha, Option::from(&pub_affine));
        let h = self.hash_to_curve_prefix(alpha, &pub_affine);
        let mut jh = Jacobian::default();
        jh.set_ge(&h);

        // U = c * pk + s * G
        let mut u = Jacobian::default();
        let pub_jacobian = Jacobian::from_ge(&pub_affine);
        self.ctx_mul
            .ecmult(&mut u, &pub_jacobian, &vrf_proof.c, &vrf_proof.s);

        // Gamma witness
        let witness_gamma = ecmult(self.ctx_mul, &vrf_proof.gamma, &vrf_proof.c);
        // Hash witness
        let witness_hash = ecmult(self.ctx_mul, &h, &vrf_proof.s);

        // V = c * gamma + s * H = witness_gamma + witness_hash
        let v = projective_add(&witness_gamma, &witness_hash);

        // c_prime = ECVRF_hash_points(G, H, pk, gamma, U, V)
        let computed_c = self.hash_points(
            &AFFINE_G,
            &h,
            &pub_affine,
            &vrf_proof.gamma,
            &jacobian_to_affine(&u),
            &jacobian_to_affine(&v),
        );

        // y = keccak256(gama.encode())
        let computed_y = keccak256_affine(&vrf_proof.gamma);

        computed_c.eq(&vrf_proof.c) && computed_y.eq(&vrf_proof.y)
    }
}

#[cfg(test)]
mod tests {
    use crate::{helper::randomize, ECVRF};
    use libsecp256k1::SecretKey;
    use rand::thread_rng;

    #[test]
    fn we_should_able_to_prove_and_verify() {
        let mut r = thread_rng();
        let secret_key = SecretKey::random(&mut r);

        // Create new instance of ECVRF
        let ecvrf = ECVRF::new(secret_key);

        // Random an alpha value
        let alpha = randomize();

        //Prove
        let r1 = ecvrf.prove(&alpha);

        // Verify
        let r2 = ecvrf.verify(&alpha, &r1);

        assert!(r2);
    }
}
