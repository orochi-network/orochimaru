use libecvrf::ECVRF;
use libsecp256k1::{curve::Scalar, SecretKey};

fn main() {
    let secret_key = SecretKey::random(&mut rand::thread_rng());
    let ecvrf = ECVRF::new(secret_key);

    let proof = ecvrf.prove(&Scalar::from_int(32));
    println!("result: {:#?}", proof);

    println!("{:?}", ecvrf.verify(&Scalar::from_int(32), &proof));
}
