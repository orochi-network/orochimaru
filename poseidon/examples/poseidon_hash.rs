use poseidon::{
    circuit::PoseidonCircuit,
    poseidon_hash::{Hash, OrchardNullifier, ConstantLength}
};
use halo2_proofs::{
    dev::MockProver,
    arithmetic::Field,
};
use std::marker::PhantomData;
use halo2curves::pasta::Fp;
use rand::rngs::OsRng;
fn main(){
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