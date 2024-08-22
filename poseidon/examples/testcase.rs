use core::marker::PhantomData;
use ff::Field;
use halo2_proofs::halo2curves::bn256::Fr;
use poseidon::{
    circuit::{PoseidonCircuit, PoseidonProver},
    poseidon_hash::{ConstantLength, Hash, OrchardNullifier},
};
use rand::rngs::OsRng;
// Provide a test case for the Poseidon hash function with real prover
fn main() {
    let rng = OsRng;

    let message = [Fr::random(rng), Fr::random(rng)];
    let output = Hash::<Fr, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

    let k = 6;
    let circuit = PoseidonCircuit::<OrchardNullifier, Fr, ConstantLength<2>, 3, 2, 2> {
        message,
        output,
        _marker: PhantomData,
        _marker2: PhantomData,
    };

    // Test with prover
    let mut prover = PoseidonProver::new(k, circuit, true);
    let proof = prover.create_proof();
    assert!(prover.verify(proof));
}
