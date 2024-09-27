extern crate alloc;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use verkletree::circuit::OrchardNullifier;
use verkletree::commitment::CommitmentScheme;

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

use verkletree::circuit::KZGStruct;

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

pub fn create_circuit(
    leaf_commitment: Fr,
    mut leaf_evaluations: Vec<Fr>,
    kzg_instance: KZGStruct,
    mut commitment_indices: Vec<usize>,
) -> Fr {
    let mut evals = [Fr::from(0); 4];

    // Use pre-allocated vectors with a known capacity to avoid reallocations
    let mut parent_evaluations: Vec<Vec<Fr>> = Vec::with_capacity(commitment_indices.len());
    let mut parent_commitment_list: Vec<Vec<G1Affine>> =
        Vec::with_capacity(commitment_indices.len());
    let mut tree_polynomials: Vec<Vec<Polynomial<Fr, Coeff>>> =
        Vec::with_capacity(commitment_indices.len());

    let commitment_indices_fr: Vec<Fr> = commitment_indices
        .iter()
        .map(|&x| Fr::from(x as u64))
        .collect();
    let evaluation_points: Vec<Fr> = commitment_indices.iter().map(|&x| OMEGA_POWER[x]).collect();

    let mut tree_size = 0;
    let total_layers = commitment_indices.len();

    // Process the leaves into layers of parent evaluations, commitments, and polynomials
    while tree_size < total_layers {
        let mut current_layer_evaluations: Vec<Fr> = Vec::with_capacity(leaf_evaluations.len() / 4);
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
    let mut final_commitments: Vec<G1Affine> = Vec::with_capacity(commitment_indices.len());
    let mut merkle_path_evaluations: Vec<Fr> = Vec::with_capacity(commitment_indices.len());
    let mut polynomial_list: Vec<Polynomial<Fr, Coeff>> =
        Vec::with_capacity(commitment_indices.len());

    commitment_indices.push(0); // Add a dummy 0 at the end of commitment_indices for the loop

    // Iterate over parent elements, commitments, and polynomials to collect proof data
    for (((commitments, evaluations), polynomials), &id) in parent_commitment_list
        .iter()
        .zip(parent_evaluations.iter())
        .zip(tree_polynomials.iter())
        .zip(commitment_indices.iter().skip(1))
    {
        let commitment = commitments.get(id).expect("msg");
        let evaluation = evaluations.get(id).expect("msg");
        let poly = polynomials.get(id).expect("msg");

        final_commitments.push(*commitment);
        merkle_path_evaluations.push(*evaluation);
        polynomial_list.push(poly.clone());
    }

    // Generate the proof
    let verkle_proof = kzg_instance.create_proof(
        evaluation_points,
        polynomial_list,
        final_commitments.clone(),
    );

    // Create the circuit
    let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
        leaf: leaf_commitment,
        commitment: final_commitments.clone(),
        proof: verkle_proof,
        path_elements: merkle_path_evaluations.clone(),
        indices: commitment_indices_fr,
        params: kzg_instance.kzg_params,
        _marker: PhantomData,
    };

    let verkle_root = *merkle_path_evaluations.last().unwrap();

    // Set up the prover
    let k = 10;
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize proving key");

    let mut prover = VerkleTreeProver::new(params.clone(), pk, circuit.clone(), true);
    let _proof = prover.create_proof(leaf_commitment, verkle_root);

    Fr::from(0) // Return the final result, adjust if needed
}

use verkletree::circuit::*;

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
        let leaf_commitment = _witness._leaf;
        let mut commitment_indices = _witness._indices;
        let mut leaf_evaluations = _witness._elements;
        let kzg_instance = self._kzg.clone();

        let mut evals = [Fr::from(0); 4];

        let mut parent_evaluations: Vec<Vec<Fr>> = Vec::with_capacity(commitment_indices.len());
        let mut parent_commitment_list: Vec<Vec<G1Affine>> =
            Vec::with_capacity(commitment_indices.len());
        let mut tree_polynomials: Vec<Vec<Polynomial<Fr, Coeff>>> =
            Vec::with_capacity(commitment_indices.len());

        let commitment_indices_fr: Vec<Fr> = commitment_indices
            .iter()
            .map(|&x| Fr::from(x as u64))
            .collect();
        let evaluation_points: Vec<Fr> =
            commitment_indices.iter().map(|&x| OMEGA_POWER[x]).collect();

        let mut tree_size = 0;
        let total_layers = commitment_indices.len();

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
        let mut final_commitments: Vec<G1Affine> = Vec::with_capacity(commitment_indices.len());
        let mut path_evaluations: Vec<Fr> = Vec::with_capacity(commitment_indices.len());
        let mut polynomial_list: Vec<Polynomial<Fr, Coeff>> =
            Vec::with_capacity(commitment_indices.len());

        commitment_indices.push(0);

        // Iterate over parent elements, commitments, and polynomials to collect proof data
        for (((commitments, evaluations), polynomials), &id) in parent_commitment_list
            .iter()
            .zip(parent_evaluations.iter())
            .zip(tree_polynomials.iter())
            .zip(commitment_indices.iter().skip(1))
        {
            let commitment = commitments.get(id).expect("msg");
            let evaluation = evaluations.get(id).expect("msg");
            let poly = polynomials.get(id).expect("msg");

            final_commitments.push(*commitment);
            path_evaluations.push(*evaluation);
            polynomial_list.push(poly.clone());
        }

        println!("{:?}", path_evaluations);

        // Generate the proof
        let verkle_proof = kzg_instance.create_proof(
            evaluation_points,
            polynomial_list,
            final_commitments.clone(),
        );

        // Create the circuit
        let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
            leaf: leaf_commitment,
            commitment: final_commitments.clone(),
            proof: verkle_proof,
            path_elements: path_evaluations.clone(),
            indices: commitment_indices_fr,
            params: kzg_instance.kzg_params,
            _marker: PhantomData,
        };

        let verkle_root = *path_evaluations.last().unwrap();

        // Set up the prover
        let k = 10;
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let vk = keygen_vk(&params, &circuit).expect("Cannot initialize verify key");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("Cannot initialize proving key");

        let mut prover = VerkleTreeProver::new(params.clone(), pk, circuit.clone(), true);
        let proof = prover.create_proof(leaf_commitment, verkle_root);
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

use ff::Field;
use rand::thread_rng;

fn main() {
    let rng = thread_rng();
    let elements: Vec<Fr> = (0..16).map(|_| Fr::random(rng.clone())).collect();

    let vk_commitment_scheme = VerkleTreeCommitmentScheme::setup(Some(2));

    let indices: Vec<usize> = vec![3, 2];
    let leaf = elements[11];

    let witness = VerkleTreeWitness {
        _leaf: leaf,
        _elements: elements,
        _indices: indices,
    };

    let root = vk_commitment_scheme.commit(witness.clone());

    let opening = vk_commitment_scheme.open(witness.clone());

    assert!(vk_commitment_scheme.verify(root, opening, witness))
}
