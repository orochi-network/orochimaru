extern crate alloc;
use crate::circuit::OrchardNullifier;
use crate::commitment::CommitmentScheme;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, VerifyingKey},
    poly::{kzg::commitment::ParamsKZG, Coeff, Polynomial},
};
use rand_core::OsRng;

pub(crate) const OMEGA_POWER: [Fr; 5] = [
    Fr::from_raw([0x01, 0, 0, 0]),
    Fr::from_raw([0x07, 0, 0, 0]),
    Fr::from_raw([0x31, 0, 0, 0]),
    Fr::from_raw([0x0157, 0, 0, 0]),
    Fr::from_raw([0x0961, 0, 0, 0]),
];

#[derive(Clone)]
pub struct VerkleTreeWitness {
    pub _leaf: Fr,
    pub _elements: Vec<Fr>,
    pub _indices: Vec<usize>,
}

pub struct VerkleTreeCommitmentScheme {
    pub _kzg: KZGStruct,
}

use crate::circuit::KZGStruct;

pub fn verkle_tree_commit(elements: Vec<Fr>, kzg: KZGStruct) -> Fr {
    let mut root = elements;
    let mut evals = [Fr::from(0); 4];

    let mut size = root.len();
    while size > 1 {
        for eval in evals.iter_mut().rev().take(4) {
            *eval = root.pop().expect("msg");
        }

        let commitment = kzg.commit(evals);
        let temp = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);

        root.push(temp);
        size = root.len();
    }

    root[0]
}

use crate::circuit::*;

impl CommitmentScheme<Fr> for VerkleTreeCommitmentScheme {
    type Commitment = Fr;
    type Opening = (ParamsKZG<Bn256>, VerifyingKey<G1Affine>, Vec<u8>);
    type PublicParams = ParamsKZG<Bn256>;
    type Witness = VerkleTreeWitness;

    fn setup(_k: Option<u32>) -> Self {
        match _k {
            Some(k) => Self {
                _kzg: KZGStruct::new(k),
            },
            _ => panic!("Invalid input parameter"),
        }
    }

    fn commit(&self, _witness: Self::Witness) -> Self::Commitment {
        verkle_tree_commit(_witness._elements, self._kzg.clone())
    }

    fn open(&self, _witness: Self::Witness) -> Self::Opening {
        let mut root = _witness._elements;
        let mut evals = [Fr::from(0); 4];

        let mut commitment_list: Vec<G1Affine> = vec![];
        let mut poly_list: Vec<Polynomial<Fr, Coeff>> = vec![];
        let mut path_elements: Vec<Fr> = vec![];

        let mut size = root.len();

        // let temp_list = []

        while size > 1 {
            for eval in evals.iter_mut().rev().take(4) {
                *eval = root.pop().expect("msg");
            }

            let poly = self._kzg.poly_from_evals(evals);
            let commitment = self._kzg.commit(evals);

            poly_list.push(poly);
            commitment_list.push(commitment);

            let temp = self
                ._kzg
                .group_to_scalar::<OrchardNullifier, 3, 2>(commitment);

            path_elements.push(temp);
            root.push(temp);
            size = root.len();
        }

        let indices_fr: Vec<Fr> = _witness
            ._indices
            .iter()
            .map(|x| Fr::from(*x as u64))
            .collect();

        let point_list: Vec<Fr> = _witness._indices.iter().map(|x| OMEGA_POWER[*x]).collect();

        let proof = self
            ._kzg
            .create_proof(point_list, poly_list, commitment_list.clone());

        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf: _witness._leaf,
            commitment: commitment_list,
            proof,
            path_elements,
            indices: indices_fr,
            params: self._kzg.kzg_params.clone(),
            _marker: PhantomData,
        };

        let k = 10;
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize proving key");

        let mut prover = VerkleTreeProver::new(params.clone(), pk, circuit.clone(), true);
        let proof = prover.create_proof(_witness._leaf, root[0]);

        (params, vk, proof)
    }

    fn verify(
        &self,
        _commitment: Self::Commitment,
        _opening: Self::Opening,
        _witness: Self::Witness,
    ) -> bool {
        let (params, vk, proof) = _opening;
        let mut verifier = VerkleTreeVerifier::new(params, vk, true);
        verifier.verify(proof, _witness._leaf, _commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ff::Field;
    use rand::thread_rng;

    #[test]
    fn test11() {
        let rng = thread_rng();
        let elements: Vec<Fr> = (0..16).map(|_| Fr::random(rng.clone())).collect();

        let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

        let indices: Vec<usize> = vec![1, 2];
        let leaf = elements[1];

        let witness = VerkleTreeWitness {
            _leaf: leaf,
            _elements: elements,
            _indices: indices,
        };

        let root = vk_commitment_scheme.commit(witness.clone());

        let opening = vk_commitment_scheme.open(witness.clone());

        assert!(vk_commitment_scheme.verify(root, opening, witness))
    }
}
