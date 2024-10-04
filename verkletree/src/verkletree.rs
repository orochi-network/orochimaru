extern crate alloc;
use crate::circuit::*;
use alloc::vec::Vec;
use core::marker::PhantomData;
use zkmemory::commitment::commitment_scheme::CommitmentScheme;

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{kzg::commitment::ParamsKZG, Coeff, Polynomial},
};

pub(crate) const OMEGA_POWER: [Fr; 5] = [
    Fr::from_raw([0x01, 0, 0, 0]),
    Fr::from_raw([0x07, 0, 0, 0]),
    Fr::from_raw([0x31, 0, 0, 0]),
    Fr::from_raw([0x0157, 0, 0, 0]),
    Fr::from_raw([0x0961, 0, 0, 0]),
];

#[derive(Clone)]
pub struct VerkleTreeWitness {
    pub leaf: Fr,
    pub elements: Vec<Fr>,
    pub indices: Vec<usize>,
}

pub struct VerkleTreeCommitmentScheme {
    pub kzg: KZGStruct,
}

pub fn verkle_tree_commit(elements: Vec<Fr>, kzg: KZGStruct) -> Fr {
    let mut root = elements;
    let mut evals = [Fr::from(0); 4];

    let mut size = root.len();
    while size > 1 {
        evals.copy_from_slice(&root[..4]);
        root = root[4..].to_vec();

        let commitment = kzg.commit(evals);
        let temp = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);

        root.push(temp);
        size = root.len();
    }

    root[0]
}

impl CommitmentScheme<Fr> for VerkleTreeCommitmentScheme {
    type Commitment = Fr;
    type Opening = (ParamsKZG<Bn256>, VerifyingKey<G1Affine>, Vec<u8>);
    type PublicParams = ParamsKZG<Bn256>;
    type Witness = VerkleTreeWitness;

    fn setup(_k: Option<u32>) -> Self {
        match _k {
            Some(k) => Self {
                kzg: KZGStruct::new(k),
            },
            _ => panic!("Invalid input parameter"),
        }
    }

    fn commit(&self, witness: Self::Witness) -> Self::Commitment {
        verkle_tree_commit(witness.elements, self.kzg.clone())
    }

    fn open(&self, witness: Self::Witness) -> Self::Opening {
        let indices = witness.indices;
        let mut leaf_evaluations = witness.elements;

        let n = 4_usize.pow(indices.len() as u32);
        assert_eq!(
            leaf_evaluations.len(),
            n,
            "number of leaf must be 4^len(indices)"
        );

        let mut index = leaf_evaluations
            .iter()
            .position(|&x| x == witness.leaf)
            .expect("Leaf not found in leaf_evaluations");

        let kzg_instance = self.kzg.clone();

        let mut evals = [Fr::from(0); 4];

        let mut parent_evaluations: Vec<Vec<Fr>> = Vec::with_capacity(indices.len());
        let mut parent_commitment_list: Vec<Vec<G1Affine>> = Vec::with_capacity(indices.len());
        let mut tree_polynomials: Vec<Vec<Polynomial<Fr, Coeff>>> =
            Vec::with_capacity(indices.len());

        let commitment_indices_fr: Vec<Fr> = indices.iter().map(|&x| Fr::from(x as u64)).collect();
        let evaluation_points: Vec<Fr> = indices.iter().map(|&x| OMEGA_POWER[x]).collect();

        let mut tree_size = 0;
        let total_layers = indices.len();

        // Process the leaves into layers of parent evaluations, commitments, and polynomials
        while tree_size < total_layers {
            let mut current_layer_evaluations: Vec<Fr> =
                Vec::with_capacity(leaf_evaluations.len() / 4);
            let mut current_layer_commitments: Vec<G1Affine> =
                Vec::with_capacity(leaf_evaluations.len() / 4);
            let mut current_layer_polynomials: Vec<Polynomial<Fr, Coeff>> =
                Vec::with_capacity(leaf_evaluations.len() / 4);

            while !leaf_evaluations.is_empty() {
                evals.copy_from_slice(&leaf_evaluations[..4]); // Copy first 4 elements
                leaf_evaluations = leaf_evaluations.split_off(4); // Efficiently split the rest of the elements

                let commitment = kzg_instance.commit(evals);
                let temp = kzg_instance.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);
                let poly = kzg_instance.poly_from_evals(evals);

                current_layer_polynomials.push(poly);
                current_layer_evaluations.push(temp);
                current_layer_commitments.push(commitment);
            }

            // Update leaf_evaluations for the next layer before moving current_layer_evaluations
            leaf_evaluations.clone_from(&current_layer_evaluations);

            parent_evaluations.push(current_layer_evaluations);
            parent_commitment_list.push(current_layer_commitments);
            tree_polynomials.push(current_layer_polynomials);

            tree_size = parent_evaluations.len();
        }

        // Initialize commitment and path lists
        let mut final_commitments: Vec<G1Affine> = Vec::with_capacity(indices.len());
        let mut path_evaluations: Vec<Fr> = Vec::with_capacity(indices.len());
        let mut polynomial_list: Vec<Polynomial<Fr, Coeff>> = Vec::with_capacity(indices.len());

        index /= 4;

        // Iterate over parent elements, commitments, and polynomials to collect proof data
        for ((commitments, evaluations), polynomials) in parent_commitment_list
            .iter()
            .zip(parent_evaluations.iter())
            .zip(tree_polynomials.iter())
        {
            let commitment = commitments
                .get(index)
                .expect("Cannot get commitment's value");
            let evaluation = evaluations.get(index).expect("can not get node value's");
            let poly = polynomials
                .get(index)
                .expect("can not get polynomial's value");

            final_commitments.push(*commitment);
            path_evaluations.push(*evaluation);
            polynomial_list.push(poly.clone());
            index /= 4
        }

        // Generate the proof
        let verkle_proof = kzg_instance.create_proof(
            evaluation_points,
            polynomial_list,
            final_commitments.clone(),
        );

        // Create the circuit
        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf: witness.leaf,
            commitment: final_commitments.clone(),
            proof: verkle_proof,
            path_elements: path_evaluations.clone(),
            indices: commitment_indices_fr,
            params: kzg_instance.kzg_params,
            _marker: PhantomData,
        };

        let verkle_root = *path_evaluations.last().unwrap();
        let k: u32 = 10;

        let mut prover = VerkleTreeProver::new(k, circuit, true);
        let (params, vk) = prover.get_verifier_params();

        let proof = prover.create_proof(witness.leaf, verkle_root);
        (params, vk, proof)
    }

    fn verify(
        &self,
        commitment: Self::Commitment,
        opening: Self::Opening,
        witness: Self::Witness,
    ) -> bool {
        let (params, vk, proof) = opening;
        let mut verifier = VerkleTreeVerifier::new(params, vk, true);
        verifier.verify(proof, witness.leaf, commitment)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ff::Field;
    use rand::thread_rng;

    #[test]
    fn test_valid_commitment_shemes() {
        let rng = thread_rng();
        let elements: Vec<Fr> = (0..16 * 4).map(|_| Fr::random(rng.clone())).collect();
        let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

        let indices: Vec<usize> = vec![3, 3, 3];
        let leaf = elements[16 * 4 - 1];
        let witness = VerkleTreeWitness {
            leaf,
            elements,
            indices,
        };

        let root = vk_commitment_scheme.commit(witness.clone());
        let opening = vk_commitment_scheme.open(witness.clone());
        assert!(vk_commitment_scheme.verify(root, opening, witness))
    }

    #[test]
    fn test_wrong_leaf() {
        let rng = thread_rng();
        let elements: Vec<Fr> = (0..16 * 4).map(|_| Fr::random(rng.clone())).collect();
        let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

        let indices: Vec<usize> = vec![3, 3, 3];
        let leaf = elements[0];
        let witness = VerkleTreeWitness {
            leaf,
            elements,
            indices,
        };

        let root = vk_commitment_scheme.commit(witness.clone());
        let opening = vk_commitment_scheme.open(witness.clone());
        assert!(!vk_commitment_scheme.verify(root, opening, witness))
    }

    #[test]
    fn test_wrong_root() {
        let rng = thread_rng();
        let elements: Vec<Fr> = (0..16 * 16).map(|_| Fr::random(rng.clone())).collect();
        let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

        let indices: Vec<usize> = vec![3, 3, 3, 3];
        let leaf = elements[16 * 16 - 1];
        let witness = VerkleTreeWitness {
            leaf,
            elements,
            indices,
        };
        let root = Fr::random(rng.clone());

        let opening = vk_commitment_scheme.open(witness.clone());
        assert!(!vk_commitment_scheme.verify(root, opening, witness))
    }

    #[test]
    #[should_panic]
    fn test_invalid_number_of_leaf() {
        let rng = thread_rng();
        let elements: Vec<Fr> = (0..16 * 16).map(|_| Fr::random(rng.clone())).collect();
        let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

        let indices: Vec<usize> = vec![3, 3, 3];
        let leaf = elements[16 * 16 - 1];
        let witness = VerkleTreeWitness {
            leaf,
            elements,
            indices,
        };

        let root = vk_commitment_scheme.commit(witness.clone());
        let opening = vk_commitment_scheme.open(witness.clone());
        assert!(!vk_commitment_scheme.verify(root, opening, witness))
    }
}
