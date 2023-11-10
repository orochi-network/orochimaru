extern crate std;
use std::println;
use core::marker::PhantomData;
use group::Curve;
use rand_core::OsRng;
use ff::{Field, PrimeField};
use rbtree::RBTree;

use halo2_proofs::{
    arithmetic::lagrange_interpolate,
    poly::{
        {Polynomial, Coeff, EvaluationDomain},
        commitment::{Blind, ParamsProver},
        kzg::commitment::ParamsKZG,
        //kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
    }
};
use halo2curves::bn256::{Bn256, G1Affine, Fr};
use crate::{
    machine::TraceRecord,
    base::Base,
    machine::MemoryInstruction,
};


/// A KZG module that commit to the memory trace through the execution trace
#[derive(Debug, Clone)]
pub struct KZGMemoryCommitment<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    kzg_params: ParamsKZG<Bn256>,
    domain: EvaluationDomain<Fr>,
    // verkle_tree: VerkleTree<u32, u32>,
    trace_record: RBTree<TraceRecord<K, V, S, T>, PhantomData<()>>,
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T> 
where
    K: Base<S>,
    V: Base<T>,
{
    /// Init a new KZG module
    pub fn init() -> Self {
        const K: u32 = 3;
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(K),
            domain: EvaluationDomain::new(1, K),
            trace_record: RBTree::new(),
        }
    }

    /// Commit the trace element tuple to G1
    pub fn commit_trace_element(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
        // Update the trace record set
        self.trace_record.insert(trace, PhantomData);
        let field_tuple = self.trace_to_field(trace);
        let poly = self.get_trace_poly(field_tuple);
        let alpha = Blind(Fr::random(OsRng));
        let commitment = self.kzg_params.commit(&poly, alpha);
        commitment.to_affine()
    }

    // Convert trace tuple elements to field elements
    // Also, fill with ZERO elements to 8 (the nearest power of 2)
    fn trace_to_field(&self, trace: TraceRecord<K, V, S, T>) -> [Fr; 8] {
        let (t, s, i, l, d) = trace.get_tuple();

        // Encode instruction to number : 1 for Write, 0 for Read
        match i {
            MemoryInstruction::Read => 
            [Fr::from(t), Fr::from(s), Fr::ZERO, 
            self.be_bytes_to_field(l.zfill32().as_mut_slice()), self.be_bytes_to_field(d.zfill32().as_mut_slice()),
            Fr::ZERO, Fr::ZERO, Fr::ZERO],
            MemoryInstruction::Write => 
            [Fr::from(t), Fr::from(s), Fr::ONE, 
            self.be_bytes_to_field(l.zfill32().as_mut_slice()), self.be_bytes_to_field(d.zfill32().as_mut_slice()),
            Fr::ZERO, Fr::ZERO, Fr::ZERO],
        }
    }

    // Use Lagrange interpolation to form the polynomial
    // representing a trace tuple element
    // We will use the points as successive powers of the field's primitive root
    fn get_trace_poly(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff> {
        let mut points_arr = [Fr::ONE; 8];
        let mut current_point = Fr::ONE;
        for i in 1..8 as usize {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            points_arr[i] = current_point;
        }
        self.domain.coeff_from_vec(lagrange_interpolate(points_arr.as_slice(), evals.as_slice()))
    }

    // Convert raw 32 bytes from big endian to Fr element
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner =
        [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }
    
    // /// Create witnesses using SHPLONK of Halo2 proving system
    // pub fn create_witness(&self, trace: TraceRecord<K, V, S, T>, points_tuple: (bool, bool, bool, bool, bool)) -> bool {
    //     false
    // }
    
}