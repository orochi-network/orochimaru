// use halo2_proofs::halo2curves::bn256::Fr;
use verkletree::circuit::*;
use verkletree::commitment::CommitmentScheme;
extern crate alloc;

fn main() {
    let k = 7;
    let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4>::setup(Some(k));
    let witness = circuit.path_elements.clone();

    let commitment = circuit.commit(witness.clone());

    let opening = circuit.open(witness.clone());

    assert!(circuit.verify(commitment, opening, witness));
}
