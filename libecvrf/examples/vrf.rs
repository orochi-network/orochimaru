use libecvrf::{
    extends::ScalarExtend,
    secp256k1::{curve::Scalar, SecretKey},
    util::thread_rng,
    ECVRF,
};

fn main() {
    let secret_key = SecretKey::random(&mut thread_rng());
    let ecvrf = ECVRF::new(secret_key);
    let alpha = Scalar::randomize();

    let proof = ecvrf.prove(&alpha);
    println!("result: {:#?}", proof);

    println!("{:?}", ecvrf.verify(&alpha, &proof));

    let smart_contract_proof = ecvrf.prove_contract(&alpha);

    println!("result: {:#?}", smart_contract_proof);
}
