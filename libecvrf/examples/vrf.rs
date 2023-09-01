use libecvrf::{
    extends::ScalarExtend,
    secp256k1::{curve::Scalar, SecretKey},
    ECVRF,
};
use std::*;

fn from_bytes(bytes: &[u8]) -> Scalar {
    if bytes.len() > 32 {
        panic!("Bytes length must be less than 32")
    }

    let mut tmp_bytes = [0u8; 32];
    tmp_bytes[0..bytes.len()].copy_from_slice(bytes);

    let mut r = Scalar::default();
    r.set_b32(&tmp_bytes).unwrap_u8();
    r
}

fn main() {
    let secret_key = SecretKey::random(&mut rand::thread_rng());
    let ecvrf = ECVRF::new(secret_key);
    let alpha = Scalar::randomize();

    let proof = ecvrf.prove(&alpha);
    println!("result: {:#?}", proof);

    println!("{:?}", ecvrf.verify(&alpha, &proof));

    let bytes = [1u8; 31];
    let t = from_bytes(&bytes);

    println!("{:?}", t);

    let smart_contract_proof = ecvrf.prove_contract(&alpha);

    println!("result: {:#?}", smart_contract_proof);
}
