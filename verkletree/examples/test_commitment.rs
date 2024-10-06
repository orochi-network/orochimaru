use verkletree::verkletree::*;
use zkmemory::commitment::commitment_scheme::CommitmentScheme;
extern crate alloc;
use ff::Field;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::thread_rng;

fn main() {
    let rng = thread_rng();
    let elements: Vec<Fr> = (0..16 * 16).map(|_| Fr::random(rng.clone())).collect();

    let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

    let indices: Vec<usize> = vec![2, 3, 3, 3];
    let leaf = elements[16 * 16 - 2];

    let witness = VerkleTreeWitness {
        leaf,
        elements,
        indices,
    };

    let root = vk_commitment_scheme.commit(witness.clone());

    let opening = vk_commitment_scheme.open(witness.clone());

    assert!(vk_commitment_scheme.verify(root, opening, witness))
}
