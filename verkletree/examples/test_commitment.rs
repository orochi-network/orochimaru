use verkletree::commitment::CommitmentScheme;
use verkletree::verkletree::*;
extern crate alloc;
use ff::Field;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::thread_rng;

fn main() {
    let rng = thread_rng();
    let elements: Vec<Fr> = (0..16 * 4).map(|_| Fr::random(rng.clone())).collect();

    let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

    let indices: Vec<usize> = vec![0, 0, 0];
    let leaf = elements[0];

    let witness = VerkleTreeWitness {
        leaf,
        elements,
        indices,
    };

    let root = vk_commitment_scheme.commit(witness.clone());

    let opening = vk_commitment_scheme.open(witness.clone());

    assert!(vk_commitment_scheme.verify(root, opening, witness))
}
