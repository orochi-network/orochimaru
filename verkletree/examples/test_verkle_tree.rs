use verkletree::circuit::*;
extern crate alloc;
use alloc::vec;
use halo2_proofs::halo2curves::bn256::Fr;

fn main() {
    let leaf = Fr::from(34213);
    let indices = vec![0, 1, 2, 1, 3, 1, 2, 0, 3];
    let (circuit, root) = create_verkle_tree_proof(leaf, indices);

    let k = 10;

    let mut prover = VerkleTreeProver::new(k, circuit, true);
    let (params, vk) = prover.get_verifier_params();

    let mut verifier = VerkleTreeVerifier::new(params, vk, true);

    let proof = prover.create_proof(leaf, root);

    assert!(verifier.verify(proof, leaf, root))
}
