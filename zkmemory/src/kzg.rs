use halo2curves::bn256::{Bn256, Fr, G1};
// use rand_core::OsRng;
use halo2_proofs::poly::EvaluationDomain;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::poly::commitment::ParamsProver;
use rand_core::OsRng;
use halo2_proofs::poly::commitment::Blind;
use halo2curves::ff::Field;

#[derive(Debug, Clone)]
/// A KZG Module using curve Bn256
pub struct KZGMemoryCommitment {
    params: ParamsKZG<Bn256>,
    domain: EvaluationDomain<Fr>
}
impl KZGMemoryCommitment {

    /// Initialize a new KZG scheme with parameters from the curve Bn256 and extended domain
    pub fn init(k: u32) -> Self {
        Self {
            params: ParamsKZG::<Bn256>::new(k),
            domain: EvaluationDomain::new(1, k)
        }
    }

    /// Commit to a polynomial represented in coefficients
    pub fn commit_polynomial(&self) -> G1 {
        let mut a = self.domain.empty_lagrange();

        for (i, a) in a.iter_mut().enumerate() {
            *a = Fr::from(i as u64);
        }

        let b = self.domain.lagrange_to_coeff(a.clone());

        let alpha = Blind(Fr::random(OsRng));

        self.params.commit(&b, alpha)
    }
}