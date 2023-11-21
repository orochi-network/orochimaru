extern crate std;
use core::marker::PhantomData;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use group::Curve;
use rand_core::OsRng;
use std::vec::Vec;

use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    plonk::Error,
    poly::{
        commitment::{Blind, CommitmentScheme, ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
        {Coeff, EvaluationDomain, Polynomial, ProverQuery, VerificationStrategy, VerifierQuery},
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};

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
    _marker1: PhantomData<K>,
    _marker2: PhantomData<V>,
}

impl<K, V, const S: usize, const T: usize> Default for KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Initialize KZG parameters
    /// K = 3 since we need the poly degree to be 2^3 = 8
    fn default() -> Self {
        Self::new()
    }
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
            _marker1: PhantomData::<K>,
            _marker2: PhantomData::<V>,
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
        for (_i, point) in (1..=8).zip(points_arr.iter_mut().skip(1)) {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            *point = current_point;
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
        //let b = bytes.as_ref();
        let inner = [0, 8, 16, 24].map(|i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }

    //WARNING: the functions below have not been tested yet
    //due to the field private error

    // Create the list of proof for KZG openings
    // Used to create a friendly KZG API opening function
    fn create_proof_sh_plonk<
        'params,
        Scheme: CommitmentScheme,
        P: Prover<'params, Scheme>,
        E: EncodedChallenge<Scheme::Curve>,
        TW: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
    >(
        &self,
        params: &'params Scheme::ParamsProver,
        // a list of point x_1,x_2,...x_n
        points_list: Vec<Scheme::Scalar>,
        // a list of polynomials p_1(x), p_2(x),...,p_n(x)
        polynomial_list: Vec<Polynomial<Scheme::Scalar, Coeff>>,
        // the list of commitment of p_1(x),p_2(x),...,p_n(x)
        commitment_list: Vec<Scheme::Curve>,
    ) -> Vec<u8>
    where
        Scheme::Scalar: WithSmallOrderMulGroup<3>,
    {
        assert!(points_list.len() == polynomial_list.len());
        assert!(points_list.len() == commitment_list.len());
        // this function, given a list of points x_1,x_2,...,x_n
        // and polynomials p_1(x),p_2(x),...,p_n(x)
        // create a witness for the value p_1(x_1), p_2(x_2),...,p_n(x_n)
        let mut transcript = TW::init(Vec::new());

        let blind = Blind::new(&mut OsRng);
        // Add the commitment the polynomial p_i(x) to transcript
        for item in &commitment_list {
            transcript.write_point(*item).unwrap();
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
            let temp = ProverQuery {
                point: points_list[i],
                poly: &polynomial_list[i],
                blind,
            };
            queries.push(temp);
        }

        let prover = P::new(params);
        prover
            .create_proof(&mut OsRng, &mut transcript, queries)
            .unwrap();

        transcript.finalize()
    }

    //Verify KZG openings
    // Used to create a friendly KZG API verification function
    fn verify_shplonk<
        'a,
        'params,
        Scheme: CommitmentScheme,
        Vr: Verifier<'params, Scheme>,
        E: EncodedChallenge<Scheme::Curve>,
        Tr: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
        Strategy: VerificationStrategy<'params, Scheme, Vr, Output = Strategy>,
    >(
        &self,
        params: &'params Scheme::ParamsVerifier,
        // // a list of point x_1,x_2,...x_n
        points_list: Vec<Scheme::Scalar>,
        // the evaluation of p_1(x_1),p_2(x_2),...,p_n(x_n)
        opening: Vec<Scheme::Scalar>,
        // the commitment of the polynomials p_1(x),p_2(x),...,p_n(x)
        commitment: Vec<Scheme::Curve>,
        // the proof of opening
        proof: &'a [u8],
    ) -> bool {
        let verifier = Vr::new(params);
        let mut check = true;
        let mut transcript = Tr::init(proof);
        // read commitment list from transcript
        let mut commitment_list = Vec::new();
        for i in 0..points_list.len() {
            let temp = transcript.read_point().unwrap();
            commitment_list.push(temp);
            // the  "proof" consists of the commitment of the polynomials p_1(x),p_2(x),...,p_n(x)
            // which should be equal to the "commitment" input, hence we need to check this
            check = check && (commitment[i] == commitment_list[i]);
        }
        // read the opening list from transcript
        let mut eval_list: Vec<<Scheme as CommitmentScheme>::Scalar> = Vec::new();
        for i in 0..points_list.len() {
            let temp: Scheme::Scalar = transcript.read_scalar().unwrap();
            eval_list.push(temp);
            // the proof "proof" consists of the evaluations of p_1(x_1), p_2(x_2),...,p_n(x_n)
            // which should be equal to the "opening" input, hence we need to check this
            check = check && (opening[i] == eval_list[i]);
        }
        // add the queries
        let mut queries = Vec::new();
        for i in 0..points_list.len() {
            let temp =
                VerifierQuery::new_commitment(&commitment_list[i], points_list[i], eval_list[i]);
            queries.push(temp);
        }
        // now, we apply the verify function from SHPLONK to return the result
        let strategy = Strategy::new(params);
        let strategy = strategy
            .process(|msm_accumulator| {
                verifier
                    .verify_proof(&mut transcript, queries.clone(), msm_accumulator)
                    .map_err(|_| Error::Opening)
            })
            .unwrap();
        check && strategy.finalize()
    }

    /// Open all fields from the trace record
    pub fn prove_trace_element(
        &self,
        trace: TraceRecord<K, V, S, T>,
        commitment: <KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve,
    ) -> Vec<u8> {
        //convert the trace to the polynomial
        //borrowed from Thang's commit function
        let poly = self.poly_from_trace(trace);
        // create the point list of opening
        let mut points_list = Vec::from([Fr::ONE; 5]);
        let mut current_point = Fr::ONE;
        for (_i, point) in (1..=5).zip(points_list.iter_mut().skip(1)) {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            *point = current_point;
        }
        // initialize the vector of commitments for the create_proof_for_shplonk function
        let mut commitment_list = Vec::new();
        commitment_list.extend([commitment; 5]);
        // initialize the vector of polynomials for the create_proof_for_shplonk function
        let mut poly_list = Vec::new();
        for _i in 0..5 {
            poly_list.push(poly.clone());
        }
        //create the proof
        self.create_proof_sh_plonk::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_,_>,
        _, Blake2bWrite<_, _, Challenge255<_>>>(
        &self.kzg_params,
        points_list.clone(),
        poly_list,
        commitment_list)
    }

    /// verify the correctness of the tract record
    pub fn verify_trace_element(
        &self,
        trace: TraceRecord<K, V, S, T>,
        commitment: <KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve,
        proof: Vec<u8>,
    ) -> bool {
        // create the opening for the polynomial from the trace
        let opening = Vec::from(self.trace_to_field(trace));
        // create the commitment list of the trace
        let mut commitment_list = Vec::new();
        commitment_list.extend([commitment; 5]);
        // create the point list of opening of the polynomial
        let mut points_list = Vec::new();
        points_list.extend([Fr::ONE; 5]);
        let mut current_point = Fr::ONE;
        for (_i, point) in (1..=5).zip(points_list.iter_mut().skip(1)) {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            *point = current_point;
        }
        // finally, verify the opening
        self.verify_shplonk::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_,_>,
        _,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<'_,_>,
        >(&self.kzg_params, points_list.clone(), opening, commitment_list,proof.as_slice())
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

        // Create a 32-bytes repr of Base 256
        let mut chunk = [0u8; 32];
        for i in 0..32 {
            chunk[i] = i as u8;
        }

        // Use my method to convert to Fr
        let fr = kzg_scheme.be_bytes_to_field(chunk.as_mut_slice());

        // Use Fr's method to convert back to bytes
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

    #[test]
    fn test_correct_memory_opening() {
        let mut kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();
        // Initialize a trace record
        let trace = TraceRecord::<B256, B256, 32, 32>::new(
            1u64,
            2u64,
            MemoryInstruction::Read,
            B256::zero(),
            B256::from(100),
        );
        //Commit the trace
        let commit = kzg_scheme.commit(trace);
        //Open the trace
        let proof = kzg_scheme.prove_trace_element(trace, commit);
        //Verify the trace
        let verify = kzg_scheme.verify_trace_element(trace, commit, proof);
        assert_eq!(verify, true);
    }

    #[test]
    fn test_wrong_memory_opening() {
        let mut kzg_scheme = KZGMemoryCommitment::<B256, B256, 32, 32>::new();
        // Initialize a trace record
        let trace = TraceRecord::<B256, B256, 32, 32>::new(
            1u64,
            2u64,
            MemoryInstruction::Read,
            B256::zero(),
            B256::from(100),
        );
        // Initialize another trace record
        // which is used to create a false proof for the first trace
        let trace2 = TraceRecord::<B256, B256, 32, 32>::new(
            2u64,
            2u64,
            MemoryInstruction::Read,
            B256::zero(),
            B256::from(100),
        );
        //Commit the first trace
        let commit = kzg_scheme.commit(trace);
        //Attempt to create the false proof of the first trace
        let commit2 = kzg_scheme.commit(trace2);
        let false_proof = kzg_scheme.prove_trace_element(trace2, commit2);
        //Verify the trace
        let verify = kzg_scheme.verify_trace_element(trace, commit, false_proof);
        assert_eq!(verify, false);
    }
}
