use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar, AFFINE_G},
    PublicKey, SecretKey, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT,
};
use rand::{thread_rng, RngCore};
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Copy, Debug)]
pub struct ECVRFProof {
    pub gamma: Affine,
    pub c: Scalar,
    pub s: Scalar,
    pub y: Scalar,
    pub pk: PublicKey,
}

impl ECVRFProof {
    pub fn new(gamma: Affine, c: Scalar, s: Scalar, y: Scalar, pk: PublicKey) -> Self {
        Self { gamma, c, s, y, pk }
    }
}

impl ToString for ECVRFProof {
    fn to_string(&self) -> String {
        let mut pub_affine: Affine = self.pk.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();
        format!(
            "gamma:\n > x: 0x{}\n > y: 0x{}\nc: 0x{}\ns: 0x{}\ny: 0x{}\npublic key:\n > x: {}\n > y: {}\n",
            hex::encode(self.gamma.x.b32()),
            hex::encode(self.gamma.y.b32()),
            hex::encode(self.c.b32()),
            hex::encode(self.s.b32()),
            hex::encode(self.y.b32()),
            hex::encode(pub_affine.x.b32()),
            hex::encode(pub_affine.y.b32())
        )
    }
}

fn ecmult(context: &ECMultContext, a: &Affine, na: &Scalar) -> Affine {
    let mut rj = Jacobian::default();
    let temp_aj = Jacobian::from_ge(a);
    context.ecmult(&mut rj, &temp_aj, na, &Scalar::from_int(0));
    let mut ra = Affine::from_gej(&rj);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

fn ecmult_gen(context: &ECMultGenContext, ng: &Scalar) -> Affine {
    let mut r = Jacobian::default();
    context.ecmult_gen(&mut r, &ng);
    let mut ra = Affine::from_gej(&r);
    ra.x.normalize();
    ra.y.normalize();
    ra
}

fn jacobian_to_affine(j: &Jacobian) -> Affine {
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

    pub fn prove(&self, alpha: &Scalar) -> ECVRFProof {
        let mut pub_affine: Affine = self.public_key.into();
        let mut secret_key: Scalar = self.secret_key.into();
        pub_affine.x.normalize();
        pub_affine.y.normalize();

        let h = self.hash_to_curve(alpha, Option::from(&pub_affine));

        // H = ECVRF_hash_to_curve(alpha, public_key)
        // gamma = H * secret_key
        let gamma = ecmult(self.ctx_mul, &h, &secret_key);

        // k = random()
        let k = randomize();

        // Calculate k * G
        let kg = ecmult_gen(self.ctx_gen, &k);

        // Calculate k * H
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

        // H = ECVRF_hash_to_curve(alpha, pk)
        let h = self.hash_to_curve(alpha, Option::from(&pub_affine));
        let mut jh = Jacobian::default();
        jh.set_ge(&h);

        // U = c * pk + s * G
        let mut u = Jacobian::default();
        let pub_jacobian = Jacobian::from_ge(&pub_affine);
        self.ctx_mul
            .ecmult(&mut u, &pub_jacobian, &vrf_proof.c, &vrf_proof.s);

        // V = c * gamma + s * H
        let mut v = Jacobian::default();
        let c_gamma = ecmult(self.ctx_mul, &h, &vrf_proof.s);
        let s_h = ecmult(self.ctx_mul, &vrf_proof.gamma, &vrf_proof.c);
        v.set_ge(&c_gamma);
        v = v.add_ge(&s_h);

        // self.ctx_mul.ecmult(&mut v, &jh, &vrf_proof.s, &vrf_proof.c);

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

fn main() {
    let mut r = thread_rng();
    let secret_key = SecretKey::random(&mut r);

    // Create new instance of ECVRF
    let ecvrf = ECVRF::new(secret_key);

    // Random an alpha value
    let alpha = randomize();

    //Prove
    let r1 = ecvrf.prove(&alpha);
    println!("{}", r1.to_string());

    // Verify
    let r2 = ecvrf.verify(&alpha, &r1);
    println!("Verified: {:?}", r2);
}
