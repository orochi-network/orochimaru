use crate::base::Base;
use ff::Field;
use halo2_proofs::arithmetic::{eval_polynomial, lagrange_interpolate};
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2curves::bn256::{Bn256, Fr};
use rand_core::OsRng;
use halo2_proofs::poly::EvaluationDomain;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::commitment::{Blind, Params};
use halo2curves::bn256::G1;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

pub struct KZGMemoryCommitment<K, V, const S: usize> {
    
}