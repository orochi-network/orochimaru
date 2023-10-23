use zkmemory::config::{DefaultConfig, ConfigArgs};
use zkmemory::machine::{RAMMachine,  StateMachine256};
use zkmemory::base::{UsizeConvertible, U256};
use zkmemory::kzg::KZGMemoryCommitment;
use halo2_proofs::arithmetic::{eval_polynomial, lagrange_interpolate};
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2curves::bn256::{Bn256, Fr};
use rand_core::OsRng;
use halo2_proofs::poly::EvaluationDomain;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::commitment::{Blind, Params};
use halo2curves::bn256::G1;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
fn main() {
    let mut sm = StateMachine256::new_custom(ConfigArgs { 
        head_layout: false, 
        stack_depth: U256::from_usize(64), 
        no_register: U256::from_usize(4), 
        buffer_size: U256::from_usize(32) }, 1024 as usize);

    let points = sm.get_cells(sm.base_address(), sm.terminal_address());

}