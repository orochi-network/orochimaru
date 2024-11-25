use libecvrf::{
    curve::Scalar,
    curve::{Affine, Field},
    extend::Randomize,
    helper::{calculate_witness_address, get_address},
    KeyPair, SecretKey, ECVRF,
};
use tiny_ec::PublicKey;

fn main() {
    let key_pair = KeyPair::new();
    let address = get_address(&key_pair.public_key);
    println!("PublicKey: {:#?}", key_pair.public_key.serialize());

    println!("Address: {}", hex::encode(address));

    let affine = Affine::new(Field::from_int(4), Field::from_int(95));
    let address = calculate_witness_address(&affine);
    println!("Address: {}", hex::encode(address));

    let secret_key = SecretKey::random();
    let public_key = PublicKey::from_secret_key(&secret_key);
    let ecvrf = ECVRF::new(secret_key);
    let alpha = Scalar::random();

    let proof = ecvrf
        .prove(&alpha)
        .expect("Failed to prove ECVRF randomness");
    println!("result: {:#?} {:#?}", &alpha, proof);

    println!("{:?}", ecvrf.verify(&public_key, &proof));

    let smart_contract_proof = ecvrf.prove_contract(&alpha);

    println!("result: {:#?}", smart_contract_proof);
}
