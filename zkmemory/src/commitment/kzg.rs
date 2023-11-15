extern crate alloc;
extern crate std;
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use group::Curve;
use rand_core::OsRng;
use rbtree::RBTree;

use crate::{
    base::Base,
    machine::TraceRecord,
    machine::MemoryInstruction,
};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    poly::{
        commitment::{Blind, CommitmentScheme, ParamsProver, Prover},
        kzg::commitment::ParamsKZG,
        {Coeff, EvaluationDomain, Polynomial, ProverQuery},
    },
    transcript::{EncodedChallenge, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

/// A KZG module that commit to the memory trace through the execution trace
#[derive(Debug, Clone)]
pub struct KZGParams<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    // Params: generators, crs, etc
    kzg_params: ParamsKZG<Bn256>,
    // Domain used for creating polynomials
    domain: EvaluationDomain<Fr>,
    // A copy of an execution trace, RBTree for later implementation of sorting
    trace_record: RBTree<TraceRecord<K, V, S, T>, PhantomData<()>>,
}

/// KZG trait for committing the memory trace elements
pub trait KZGMemoryCommitment<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Init a new KZG module
    fn init() -> KZGParams<K, V, S, T>;

    /// Commit the trace element tuple to G1
    fn commit_trace_element(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine;

    /// Convert trace tuple elements to field elements
    /// Also, fill with ZERO elements to 8 (the nearest power of 2)
    fn trace_to_field(&self, trace: TraceRecord<K, V, S, T>) -> [Fr; 8];

    /// Use Lagrange interpolation to form the polynomial
    /// representing a trace tuple element
    /// We will use the points as successive powers of the field's primitive root
    fn get_trace_poly(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff>;

    /// Convert raw 32 bytes from big endian to Fr element
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr;

    /// Create witness
    fn create_proof_sh_plonk<
        'params,
        Scheme: CommitmentScheme,
        P: Prover<'params, Scheme>,
        E: EncodedChallenge<Scheme::Curve>,
        TW: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
    >(
        params: &'params Scheme::ParamsProver,
        // a list of point x_1,x_2,...x_n
        points_list: Vec<Scheme::Scalar>,
        // a list of polynomials p_1(x), p_2(x),...,p_n(x)
        polynomial_list: Vec<Polynomial<Scheme::Scalar, Coeff>>,
    ) -> Vec<u8>
    where
        Scheme::Scalar: WithSmallOrderMulGroup<3>;
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T> for KZGParams<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn init() -> Self {
        const K: u32 = 3;
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(K),
            domain: EvaluationDomain::new(1, K),
            trace_record: RBTree::new(),
        }
    }

    fn commit_trace_element(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
        // Update the trace record set
        self.trace_record.insert(trace, PhantomData);
        let field_tuple = self.trace_to_field(trace);
        let poly = self.get_trace_poly(field_tuple);
        let alpha = Blind(Fr::random(OsRng));
        let commitment = self.kzg_params.commit(&poly, alpha);
        commitment.to_affine()
    }

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

    fn get_trace_poly(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff> {
        let mut points_arr = [Fr::ONE; 8];
        let mut current_point = Fr::ONE;
        for i in 1..8 as usize {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            points_arr[i] = current_point;
        }
        self.domain.coeff_from_vec(lagrange_interpolate(
            points_arr.as_slice(),
            evals.as_slice(),
        ))
    }

    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner = [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }

    fn create_proof_sh_plonk<
        'params,
        Scheme: CommitmentScheme,
        P: Prover<'params, Scheme>,
        E: EncodedChallenge<Scheme::Curve>,
        TW: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
    >(
        params: &'params Scheme::ParamsProver,
        // a list of point x_1,x_2,...x_n
        points_list: Vec<Scheme::Scalar>,
        // a list of polynomials p_1(x), p_2(x),...,p_n(x)
        polynomial_list: Vec<Polynomial<Scheme::Scalar, Coeff>>,
    ) -> Vec<u8>
    where
        Scheme::Scalar: WithSmallOrderMulGroup<3>,
    {
        // this function, given a list of points x_1,x_2,...,x_n
        // and polynomials p_1(x),p_2(x),...,p_n(x)
        // create a witness for the value p_1(x_1), p_2(x_2),...,p_n(x_n)
        let mut transcript = TW::init(Vec::new());

        let blind = Blind::new(&mut OsRng);
        // Commit the polynomial p_i(x)
        for i in 0..polynomial_list.len() {
            let a = params.commit(&polynomial_list[i], blind).to_affine();
            transcript.write_point(a).unwrap();
        }
        // evaluate the values p_i(x_i) for i=1,2,...,n
        for i in 0..polynomial_list.len() {
            let av = eval_polynomial(&polynomial_list[i], points_list[i]);
            transcript.write_scalar(av).unwrap();
        }

        // this query is used to list all the values p_1(x_1), p_2(x_2),...,p_n(x_n)
        // in the query list of shplonk prover

        let mut queries: Vec<ProverQuery<'_, <Scheme as CommitmentScheme>::Curve>> = Vec::new();
        for i in 0..polynomial_list.len() {
            let mut temp = ProverQuery {
                point: points_list[i],
                poly: &polynomial_list[i],
                blind,
            };
            queries.push(temp);
        }
        // create the proof
        let prover = P::new(params);
        prover
            .create_proof(&mut OsRng, &mut transcript, queries)
            .unwrap();

        transcript.finalize()
    }
}