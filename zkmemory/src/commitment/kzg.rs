extern crate alloc;
extern crate std;
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use group::Curve;
use rand_core::OsRng;

use crate::{base::Base, machine::MemoryInstruction, machine::TraceRecord};
use halo2_proofs::{
    arithmetic::{eval_polynomial, lagrange_interpolate},
    plonk::Error,
    poly::{
        commitment::{Blind, CommitmentScheme, ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK,VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
        {Coeff, EvaluationDomain, Polynomial, ProverQuery, VerificationStrategy, VerifierQuery},
    },
    transcript::{
       Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
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
    _marker1: PhantomData<K>,
    _marker2: PhantomData<V>,
}


/// KZG trait for committing the memory trace elements


impl<K, V, const S: usize, const T: usize> KZGParams<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn init() -> Self {
        const K: u32 = 3;
        Self {
            kzg_params: ParamsKZG::<Bn256>::new(K),
            domain: EvaluationDomain::new(1, K),
            _marker1: PhantomData::<K>,
            _marker2: PhantomData::<V>,
        }
    }


      /// Commit a trace record in an execution trace
    /// The RBtree in the struct also updates the records
    pub fn commit(&mut self, trace: TraceRecord<K, V, S, T>) -> G1Affine {
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

   // Convert 8 field elements of a trace record
    // into a polynomial
    fn get_trace_poly(&self, evals: [Fr; 8]) -> Polynomial<Fr, Coeff> {
        let mut points_arr = [Fr::ONE; 8];
        let mut current_point = Fr::ONE;

        // We use successive powers of primitive roots as points
        // We use elements in trace record to be the evals
        // 3 last evals should be ZERO
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
        commitment_list:Vec<Scheme::Curve>,
    ) -> Vec<u8>
    where
        Scheme::Scalar: WithSmallOrderMulGroup<3>,
    {
        assert!(points_list.len()==polynomial_list.len());
        assert!(points_list.len()==commitment_list.len());
        // this function, given a list of points x_1,x_2,...,x_n
        // and polynomials p_1(x),p_2(x),...,p_n(x)
        // create a witness for the value p_1(x_1), p_2(x_2),...,p_n(x_n)
        let mut transcript = TW::init(Vec::new());

        let blind = Blind::new(&mut OsRng);
        // Add the commitment the polynomial p_i(x) to transcript
        for i in 0..polynomial_list.len() {
            transcript.write_point(commitment_list[i]).unwrap();
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
        // create the proof
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
        // the proof of opening
        proof: &'a [u8],
    ) -> bool {
        let verifier = Vr::new(params);

        let mut transcript = Tr::init(proof);
        // read commitment list from transcript
        let mut commitment_list = Vec::new();
        for _i in 0..points_list.len() {
            let temp = transcript.read_point().unwrap();
            commitment_list.push(temp);
        }
        // read the point list from transcript
        let mut polynomial_list = Vec::new();
        for _i in 0..points_list.len() {
            let temp: Scheme::Scalar = transcript.read_scalar().unwrap();
            polynomial_list.push(temp);
        }
        // add the queries
        let mut queries = Vec::new();
        for i in 0..points_list.len() {
            let temp = VerifierQuery::new_commitment(
                &commitment_list[i],
                points_list[i],
                polynomial_list[i]);
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

        strategy.finalize()
    }


 // Open all fields from the trace record
    fn prove_trace_element
    (&self, trace: TraceRecord<K, V, S, T>,
    commitment: <KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve) -> Vec<u8> {
        //convert the trace to the polynomial
        //borrowed from Thang's commit function
        const K: u32 = 3;
        let field_tuple = self.trace_to_field(trace);
        let poly = self.get_trace_poly(field_tuple);
        // create the point list of opening
        let mut points_list = Vec::new();
        points_list.extend([Fr::ONE; 5]);
        let mut current_point = Fr::ONE;
        for i in 1..5 as usize {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            points_list[i] = current_point;
        }
        // initialize the vector of commitments for the create_proof_for_shplonk function
        let mut commitment_list=Vec::new();
        commitment_list.extend([commitment; 5]);
        // initialize the vector of polynomials for the create_proof_for_shplonk function
        let mut poly_list = Vec::new();
        for _i in 0..5
        {
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
    
// verify the correctness of the tract record
    fn verify_trace_element(&self, proof: Vec<u8>) -> bool {
        const K: u32 = 3;
        // create the point list of opening
        let mut points_list = Vec::new();
        points_list.extend([Fr::ONE; 5]);
        let mut current_point = Fr::ONE;
        for i in 1..5 as usize {
            current_point *= Fr::MULTIPLICATIVE_GENERATOR;
            points_list[i] = current_point;
        }
        // finally, verify the opening
        self.verify_shplonk::< 
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_,_>,
        _,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<'_,_>,
        >(&self.kzg_params, points_list.clone(), proof.as_slice())
    }
}
