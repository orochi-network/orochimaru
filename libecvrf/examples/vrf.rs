use libecvrf::{
    extends::ScalarExtend,
    helper::{calculate_witness_address, get_address},
    secp256k1::{curve::Scalar, SecretKey},
    util::thread_rng,
    KeyPair, ECVRF,
};
use libsecp256k1::curve::{Affine, Field};

fn main() {
    let key_pair = KeyPair::new();
    let address = get_address(&key_pair.public_key);
    println!(
        "PublicKey: {:#?}",
        key_pair.public_key.serialize_compressed()
    );

    println!("Address: {}", hex::encode(address));

    let affine = Affine::new(Field::from_int(4), Field::from_int(95));
    let address = calculate_witness_address(&affine);
    println!("Address: {}", hex::encode(address));

    let secret_key = SecretKey::random(&mut thread_rng());
    let ecvrf = ECVRF::new(secret_key);
    let alpha = Scalar::randomize();

    let proof = ecvrf
        .prove(&alpha)
        .expect("Failed to prove ECVRF randomness");
    println!("result: {:#?} {:#?}", &alpha, proof);

    println!("{:?}", ecvrf.verify(&alpha, &proof));

    let smart_contract_proof = ecvrf.prove_contract(&alpha);

    println!("result: {:#?}", smart_contract_proof);
}
