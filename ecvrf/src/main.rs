use libsecp256k1::{
    curve::{Affine, ECMultContext, ECMultGenContext, Field, Jacobian, Scalar, AFFINE_G},
    sign, verify, PublicKey, SecretKey, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT,
};
use rand::{thread_rng, Rng, RngCore};
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Copy, Debug)]
pub struct ECVRFProof {
    pub gamma: Jacobian,
    pub c: Scalar,
    pub s: Scalar,
    pub y: Scalar,
    pub pk: PublicKey,
}

impl ECVRFProof {
    pub fn new(gamma: Jacobian, c: Scalar, s: Scalar, y: Scalar, pk: PublicKey) -> Self {
        Self { gamma, c, s, y, pk }
    }
}

/// Compute the Keccak-256 hash of input bytes.
// Solidity Keccak256 variant
pub fn keccak256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}

pub fn keccak256_to_scala<S>(bytes: S) -> Scalar
where
    S: AsRef<[u8]>,
{
    let mut digest = keccak256(bytes);
    let r = Scalar::default();
    r.fill_b32(&mut digest);
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

// Field value to scalar with normalize
pub fn field_to_scalar(f: &Field) -> Scalar {
    let mut r = Scalar::default();
    let mut tf = f.clone();
    tf.normalize();
    r.set_b32(&tf.b32()).unwrap_u8();
    r
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
        match y {
            Some(v) => {
                r = r.add_ge(v);
                let mut p = Affine::default();
                p.set_gej(&r);
                p
            }
            None => {
                let mut p = Affine::default();
                p.set_gej(&r);
                p
            }
        }
    }

    // keccak256 cheaper on Ethereum
    pub fn hash_points(
        &self,
        g: &Affine,
        h: &Affine,
        pk: &Affine,
        gamma: &Jacobian,
        kg: &Jacobian,
        kh: &Jacobian,
    ) -> Scalar {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        let mut buf_affine: Affine;
        let mut buf_jacobian: Jacobian;

        // G
        buf_affine = g.clone();
        buf_affine.x.normalize();
        buf_affine.y.normalize();
        hasher.update(buf_affine.x.b32().as_ref());
        hasher.update(buf_affine.y.b32().as_ref());

        // H
        buf_affine = h.clone();
        buf_affine.x.normalize();
        buf_affine.y.normalize();
        hasher.update(buf_affine.x.b32().as_ref());
        hasher.update(buf_affine.y.b32().as_ref());

        // pk
        buf_affine = pk.clone();
        buf_affine.x.normalize();
        buf_affine.y.normalize();
        hasher.update(buf_affine.x.b32().as_ref());
        hasher.update(buf_affine.y.b32().as_ref());

        // gamma
        buf_jacobian = gamma.clone();
        buf_jacobian.x.normalize();
        buf_jacobian.y.normalize();
        hasher.update(buf_jacobian.x.b32().as_ref());
        hasher.update(buf_jacobian.y.b32().as_ref());

        // k * G
        buf_jacobian = kg.clone();
        buf_jacobian.x.normalize();
        buf_jacobian.y.normalize();
        hasher.update(buf_jacobian.x.b32().as_ref());
        hasher.update(buf_jacobian.y.b32().as_ref());

        // k * H
        buf_jacobian = kh.clone();
        buf_jacobian.x.normalize();
        buf_jacobian.y.normalize();
        hasher.update(buf_jacobian.x.b32().as_ref());
        hasher.update(buf_jacobian.y.b32().as_ref());

        hasher.finalize(&mut output);
        let mut r = Scalar::default();
        r.set_b32(&output).unwrap_u8();
        r
    }

    // @TODO i think we should remove secret key from the memory after do the calculation
    pub fn prove(&self, alpha: &Scalar) -> ECVRFProof {
        let pub_affine: Affine = self.public_key.into();
        let h = self.hash_to_curve(alpha, Option::from(&pub_affine));
        let mut gamma = Jacobian::default();
        let secret_key: Scalar = self.secret_key.into();

        // H = ECVRF_hash_to_curve(alpha, public_key)
        // gamma = H * secret_key
        gamma.set_ge(&h);
        self.ctx_gen.ecmult_gen(&mut gamma, &secret_key);

        // k = random()
        let k = randomize();

        // Calculate k * G
        let mut kg = Jacobian::default();
        self.ctx_gen.ecmult_gen(&mut kg, &k);

        // Calculate k * H
        let mut kh = Jacobian::default();
        self.ctx_gen.ecmult_gen(&mut kh, &k);

        // c = ECVRF_hash_points(G, H, public_key, gamma, k * G, k * H)
        let c = self.hash_points(&AFFINE_G, &h, &pub_affine, &gamma, &kg, &kh);

        // s = (k - c * secret_key) mod p
        let mut neg_c = c.clone();
        neg_c.cond_neg_assign(1.into());
        let s = normalize_scalar(&(k + neg_c * secret_key));

        // y = keccak256(gama.encode())
        let mut y = Scalar::default();
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        let mut gama_mut = gamma.clone();
        gama_mut.x.normalize();
        gama_mut.y.normalize();
        hasher.update(gama_mut.x.b32().as_ref());
        hasher.update(gama_mut.y.b32().as_ref());
        hasher.finalize(&mut output);
        y.set_b32(&output).unwrap_u8();

        ECVRFProof::new(gamma, c, s, y, self.public_key)
    }

    pub fn verify(self, alpha: &Scalar, vrf_proof: ECVRFProof) -> bool {
        let pub_affine: Affine = self.public_key.into();

        // H = ECVRF_hash_to_curve(alpha, pk)
        let mut h = self.hash_to_curve(alpha, Option::from(&pub_affine));
        h.x.normalize();
        h.y.normalize();
        let mut jh = Jacobian::default();
        jh.set_ge(&h);

        // U = c * pk + s * G
        let mut u = Jacobian::default();
        let mut pub_jacobian = Jacobian::default();
        pub_jacobian.set_ge(&pub_affine);
        self.ctx_mul
            .ecmult(&mut u, &pub_jacobian, &vrf_proof.c, &vrf_proof.s);

        // V = c * gamma + s * H
        let mut v = Jacobian::default();
        self.ctx_mul.ecmult(&mut v, &jh, &vrf_proof.s, &vrf_proof.c);

        // c_prime = ECVRF_hash_points(G, H, pk, gamma, U, V)
        let computed_c = self.hash_points(&AFFINE_G, &h, &pub_affine, &vrf_proof.gamma, &u, &v);

        // y = keccak256(gama.encode())
        let mut computed_y = Scalar::default();
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        let mut gama_mut = vrf_proof.gamma.clone();
        gama_mut.x.normalize();
        gama_mut.y.normalize();
        hasher.update(gama_mut.x.b32().as_ref());
        hasher.update(gama_mut.y.b32().as_ref());
        hasher.finalize(&mut output);
        computed_y.set_b32(&output).unwrap_u8();

        println!("Computed C: {:?}", computed_c);
        println!("Proof C: {:?}", vrf_proof.c);
        println!("Is c the same? {:?}", computed_c.eq(&vrf_proof.c));
        println!("Is y the same? {:?}", computed_y.eq(&vrf_proof.y));

        computed_c.eq(&vrf_proof.c) && computed_y.eq(&vrf_proof.y)
    }
}

fn main() {
    // let secret_key = SecretKey::random(&mut r);
    let secret_key = SecretKey::parse(
        hex::decode("cbc9d3dfb474233a148fba708e1b3683de8816fc7e35e28e96a831a117075f7a")
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    let ecvrf = ECVRF::new(secret_key);
    /*
    let r = ecvrf.hash_to_curve(
        &Scalar::from_int(1),
        Option::from(&Affine::new(Field::from_int(1), Field::from_int(2))),
    ); */

    let r1 = ecvrf.prove(&Scalar::from_int(1));

    println!("{:?}", r1);

    let r2 = ecvrf.verify(&Scalar::from_int(1), r1);

    println!("Verified: {:?}", r2);
}
