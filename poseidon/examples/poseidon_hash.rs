use halo2_proofs::{arithmetic::Field, dev::MockProver};
use halo2curves::pasta::Fp;
use poseidon::{
    circuit::PoseidonCircuit,
    poseidon_hash::{ConstantLength, Hash, OrchardNullifier},
};
use rand::rngs::OsRng;
use std::marker::PhantomData;
fn main() {
    let rng = OsRng;

    let message = [Fp::random(rng), Fp::random(rng)];
    let output = Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

    let k = 6;
    let circuit = PoseidonCircuit::<OrchardNullifier, Fp, ConstantLength<2>, 3, 2, 2> {
        message,
        output,
        _marker: PhantomData,
        _marker2: PhantomData,
    };
    let prover = MockProver::run(k, &circuit, vec![]).expect("cannot prove");
    assert_eq!(prover.verify(), Ok(()))
}
