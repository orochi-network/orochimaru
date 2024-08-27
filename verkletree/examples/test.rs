use ff::Field;
use verkletree::circuit::*;
use zkmemory::commitment::kzg::create_kzg_proof;
extern crate alloc;
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use group::Curve;
use halo2_proofs::{
    arithmetic::lagrange_interpolate,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        CurveAffineExt,
    },
    poly::{
        commitment::{Blind, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        Coeff, EvaluationDomain, Polynomial,
    },
    transcript::{Blake2bWrite, Challenge255},
};
use poseidon::poseidon_hash::{ConstantLength, Hash, Spec};
use rand::thread_rng;
use rand_core::OsRng;

#[derive(Debug, Clone)]
pub struct KZGStruct {
    kzg_params: ParamsKZG<Bn256>,
    domain: EvaluationDomain<Fr>,
}

pub(crate) const OMEGA_POWER: [Fr; 5] = [
    Fr::from_raw([0x01, 0, 0, 0]),
    Fr::from_raw([0x07, 0, 0, 0]),
    Fr::from_raw([0x31, 0, 0, 0]),
    Fr::from_raw([0x0157, 0, 0, 0]),
    Fr::from_raw([0x0961, 0, 0, 0]),
];

impl KZGStruct {
    /// Initialize KZG parameters
    pub fn new(k: u32) -> Self {
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(k),
            domain: EvaluationDomain::new(1, k),
        }
    }

    /// Convert a given list into a polynomial
    pub fn poly_from_evals(&self, evals: [Fr; 4]) -> Polynomial<Fr, Coeff> {
        self.domain
            .coeff_from_vec(lagrange_interpolate(&OMEGA_POWER[0..4], &evals))
    }

    /// Commit the polynomial
    pub fn commit(&self, evals: [Fr; 4]) -> G1Affine {
        self.kzg_params
            .commit(&self.poly_from_evals(evals), Blind(Fr::random(OsRng)))
            .to_affine()
    }

    /// Create proof for multiple polynomial openings
    pub fn create_proof(
        &self,
        point: Vec<Fr>,
        polynomial: Vec<Polynomial<Fr, Coeff>>,
        commitment: Vec<G1Affine>,
    ) -> Vec<u8> {
        create_kzg_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        >(&self.kzg_params, point, polynomial, commitment)
    }

    /// Hash a group element to an element in Fr
    pub fn group_to_scalar<S: Spec<Fr, W, R>, const W: usize, const R: usize>(
        &self,
        commitment: G1Affine,
    ) -> Fr {
        let (x_coordinate, y_coordinate) = commitment.into_coordinates();
        let x_coordinate_fr =
            Fr::from_bytes(&x_coordinate.to_bytes()).expect("Cannot convert x to Fr");
        let y_coordinate_fr =
            Fr::from_bytes(&y_coordinate.to_bytes()).expect("cannot convert y into Fr");

        Hash::<Fr, S, ConstantLength<2>, W, R>::init().hash([x_coordinate_fr, y_coordinate_fr])
    }
}

/// Create a valid verkle tree proof for the purpose of testing
pub fn create_verkle_tree_proof(
    leaf: Fr,
    indices: Vec<usize>,
) -> (VerkleTreeCircuit<OrchardNullifier, 3, 2, 4>, Fr) {
    let rng = thread_rng();
    let kzg = KZGStruct::new(2);
    let mut commitment_list: Vec<G1Affine> = vec![];
    let mut poly_list: Vec<Polynomial<Fr, Coeff>> = vec![];
    let mut path_elements: Vec<Fr> = vec![];
    let mut temp = leaf;
    for i in 0..indices.len() {
        let mut evals = [0; 4].map(|_| Fr::random(rng.clone()));
        evals[indices[i]] = temp;

        let poly = kzg.poly_from_evals(evals);

        let commitment = kzg.commit(evals);

        poly_list.push(poly);
        commitment_list.push(commitment);

        temp = kzg.group_to_scalar::<OrchardNullifier, 3, 2>(commitment);
        path_elements.push(temp)
    }

    let root = temp;

    let indices_fr: Vec<Fr> = indices.iter().map(|x| Fr::from(*x as u64)).collect();

    let point_list: Vec<Fr> = indices.iter().map(|x| OMEGA_POWER[*x]).collect();

    let proof = kzg.create_proof(point_list, poly_list, commitment_list.clone());

    let circuit = VerkleTreeCircuit::<OrchardNullifier, 3, 2, 4> {
        leaf,
        commitment: commitment_list,
        proof,
        path_elements,
        indices: indices_fr,
        params: kzg.kzg_params,
        _marker: PhantomData,
    };
    (circuit, root)
}

fn main() {
    let leaf = Fr::from(34213);
    let indices = vec![0, 1, 2, 1, 3, 1, 2, 0, 3];
    let (circuit, root) = create_verkle_tree_proof(leaf, indices);

    let k = 10;
    let mut prover = VerkleTreeProver::new(k, circuit, true);
    let proof = prover.create_proof(leaf, root);
    assert!(prover.verify(proof, leaf, root))
}
