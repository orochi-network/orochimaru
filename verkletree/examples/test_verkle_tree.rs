use verkletree::circuit::*;
extern crate alloc;
use alloc::vec;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use rand_core::OsRng;

fn main() {
    let leaf = Fr::from(34213);
    let indices = vec![0, 1, 2, 1, 3, 1, 2, 0, 3];
    let (circuit, root) = create_verkle_tree_proof(leaf, indices);

    let k = 10;
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize proving key");

    let mut prover = VerkleTreeProver::new(params.clone(), pk, circuit.clone(), true);
    let mut verifier = VerkleTreeVerifier::new(params, vk, true);

    let proof = prover.create_proof(leaf, root);

    assert!(verifier.verify(proof, leaf, root))
}
