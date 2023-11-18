extern crate std;
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use group::Curve;
use rand_core::OsRng;

use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use halo2_proofs::{
    arithmetic::lagrange_interpolate,
    poly::{
        commitment::{Blind, ParamsProver},
        kzg::commitment::ParamsKZG,
        {Coeff, EvaluationDomain, Polynomial},
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

/// A KZG module that commit to the memory trace through the execution trace
#[derive(Debug, Clone)]
pub struct KZGMemoryCommitment<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    // Params: generators, crs, etc
    kzg_params: ParamsKZG<Bn256>,
    // Domain used for creating polynomials
    domain: EvaluationDomain<Fr>,
    // Phantom data for K and V
    _marker_k: PhantomData<K>,
    _marker_v: PhantomData<V>,
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Initialize KZG parameters
    /// K = 3 since we need the poly degree to be 2^3 = 8
    pub fn new() -> Self {
        const K: u32 = 3;
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(K),
            domain: EvaluationDomain::new(1, K),
            _marker_k: PhantomData::<K>,
            _marker_v: PhantomData::<V>,
        }
    }

    /// Commit a trace record in an execution trace
    pub fn commit(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
        // Convert trace record into polynomial
        let poly = self.poly_from_trace(trace);

        // Commit the polynomial using Halo2's code
        let alpha = Blind(Fr::random(OsRng));
        let commitment = self.kzg_params.commit(&poly, alpha);
        commitment.to_affine()
    }

    // Convert a trace record to 8 field elements
    // The last 3 elements will be ZERO
    fn trace_to_field(&self, trace: TraceRecord<K, V, S, T>) -> [Fr; 8] {
        let (t, s, i, l, d) = trace.get_tuple();

        // Encode instruction to number : 1 for Write, 0 for Read
        match i {
            MemoryInstruction::Read => [
                Fr::from(t),
                Fr::from(s),
                Fr::ZERO,
                self.be_bytes_to_field(l.zfill32().as_mut_slice()),
                self.be_bytes_to_field(d.zfill32().as_mut_slice()),
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
            ],
            MemoryInstruction::Write => [
                Fr::from(t),
                Fr::from(s),
                Fr::ONE,
                self.be_bytes_to_field(l.zfill32().as_mut_slice()),
                self.be_bytes_to_field(d.zfill32().as_mut_slice()),
                Fr::ZERO,
                Fr::ZERO,
                Fr::ZERO,
            ],
        }
    }

    // Convert the trace record into a polynomial
    fn poly_from_trace(&self, trace: TraceRecord<K, V, S, T>) -> Polynomial<Fr, Coeff> {
        let evals = self.trace_to_field(trace);
        self.poly_from_evals(evals)
    }

    // Convert 8 field elements of a trace record
    // into a polynomial
    fn poly_from_evals(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff> {
        let mut points_arr = [Fr::ONE; 8];
        let mut current_point = Fr::ONE;

        // We use successive powers of primitive roots as points
        // We use elements in trace record to be the evals
        // 3 last evals should be ZERO
        for i in 1..8 as usize {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            points_arr[i] = current_point;
        }

        // Use Lagrange interpolation
        self.domain.coeff_from_vec(lagrange_interpolate(
            points_arr.as_slice(),
            evals.as_slice(),
        ))
    }

    // Convert 32 bytes number to field elements
    // This is made compatible with the Fr endianess
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner = [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        let result = Fr::from_raw(inner);
        result
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{base::B256, machine::AbstractTraceRecord};
    use halo2_proofs::arithmetic::eval_polynomial;

    #[test]
    fn test_conversion_fr() {
        let kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();
        let mut chunk = [0u8; 32];
        for i in 0..32 {
            chunk[i] = i as u8;
        }

        let fr = kzg_scheme.be_bytes_to_field(chunk.as_mut_slice());
        let chunk_fr: [u8; 32] = fr.try_into().unwrap();

        assert_eq!(chunk_fr, chunk);
    }

    #[test]
    fn test_record_polynomial_conversion() {
        let kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();

        // Initialize a trace record
        let trace = TraceRecord::<B256, B256, 32, 32>::new(
            1u64,
            2u64,
            MemoryInstruction::Read,
            B256::zero(),
            B256::from(100),
        );

        // Get the polynomial
        let poly_trace = kzg_scheme.poly_from_trace(trace);

        // Get only the evals, which is the trace record's elements converted to field elements
        let poly_evals = kzg_scheme.trace_to_field(trace);

        // Test each eval values
        let mut base_index = Fr::ONE;
        for i in 0..8 {
            assert_eq!(eval_polynomial(&poly_trace, base_index), poly_evals[i]);
            base_index *= Fr::MULTIPLICATIVE_GENERATOR;
        }
    }
}
