use halo2_proofs::arithmetic::lagrange_interpolate;
use halo2curves::bn256::{Bn256, Fr, G1, G1Affine};
use crate::base::Base;
use halo2_proofs::poly::{EvaluationDomain, Polynomial, Coeff};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::poly::commitment::ParamsProver;
use rand_core::OsRng;
use halo2_proofs::poly::commitment::Blind;
use halo2curves::ff::Field;
use halo2_proofs::arithmetic::best_multiexp;

extern crate alloc;
use alloc::vec::Vec;

use crate::machine::StateMachine;

#[derive(Debug)]
/// A KZG Module using curve Bn256
pub struct KZGMemoryCommitment<K, V, const S: usize>
where
    K: Base<S>,
    V: Base<S> 
{
    params: ParamsKZG<Bn256>,
    domain: EvaluationDomain<Fr>,
    machine: StateMachine<K, V, S>,
    common_reference_string: Vec<G1Affine>
}
impl<K, V, const S: usize> KZGMemoryCommitment<K, V, S>
where
    K: Base<S>,
    V: Base<S>
{
    /// Initialize a new KZG scheme with parameters from the curve Bn256 and extended domain
    pub fn init(k: u32, machine: StateMachine<K, V, S>) -> Self {
        let params = ParamsKZG::<Bn256>::new(k);
        let crs = Vec::from(params.get_g());
        Self {
            params: params,
            domain: EvaluationDomain::new(1, k),
            machine: machine,
            common_reference_string: crs
        }
    }

    /// Get all cells from the memory section 
    pub fn get_cells_from_ram(&mut self) -> Vec<(K, V)> {
        self.machine.get_cells(self.machine.base_address(), self.machine.terminal_address())
    }

    /// Commit to a polynomial represented in coefficients
    pub fn commit_polynomial(&self, poly: Polynomial<Fr, Coeff>) -> G1 {
        let alpha = Blind(Fr::random(OsRng));
        self.params.commit(&poly, alpha)
    }

    /// Another function used to commit the polynomial
    /// This function copies the code from Halo2 for debugging only
    pub fn commit_polynomial_2(&self, poly: Polynomial<Fr, Coeff>) -> G1 {
        let mut scalars = Vec::with_capacity(poly.len());
        scalars.extend(poly.iter());
        let bases = &self.common_reference_string;
        let size = scalars.len();
        assert!(bases.len() >= size);
        best_multiexp(&scalars, &bases[0..size])
    }

    /// Use lagrange interpolation to form a polynomial from points
    pub fn lagrange_from_points(&self, points: Vec<(Fr, Fr)>) -> Polynomial<Fr, Coeff> {
        let point: Vec<Fr> = points.iter().map(|&(a, _)| a).collect();
        let value: Vec<Fr> = points.iter().map(|&(_, b)| b).collect();
        let poly_coefficients = lagrange_interpolate(&point, &value);
        self.domain.coeff_from_vec(poly_coefficients)
    }

    /// Convert raw bytes from big endian to Fr element
    pub fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner =
        [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }

    /// Convert points of type Base<S> to Fr element
    pub fn base_to_field_elements(&self, points: Vec<(K, V)>) -> Vec<(Fr, Fr)> {
        let mut field_point_vec: Vec<(Fr, Fr)> = Vec::new();
        for (point, value) in points.into_iter() {
            field_point_vec.push((
                self.be_bytes_to_field(point.zfill32().as_mut_slice()), 
                self.be_bytes_to_field(value.zfill32().as_mut_slice())));
        }
        field_point_vec
    }

    /// Commit the memory state
    pub fn commit_memory_state(&mut self) -> G1 {
        let cells = self.get_cells_from_ram();
        let points_vec = self.base_to_field_elements(cells);
        let state_poly = self.lagrange_from_points(points_vec);
        let commitment = self.commit_polynomial(state_poly);
        commitment
    }

    /// Commit the memory state
    pub fn commit_memory_state_2(&mut self) -> G1 {
        let cells = self.get_cells_from_ram();
        let points_vec = self.base_to_field_elements(cells);
        let state_poly = self.lagrange_from_points(points_vec);
        let commitment = self.commit_polynomial_2(state_poly);
        commitment
    }

    /// Get the memory state represented as a polynomial
    pub fn get_poly_state(&mut self) -> Polynomial<Fr, Coeff> {
        let cells = self.get_cells_from_ram();
        let points_vec = self.base_to_field_elements(cells);
        self.lagrange_from_points(points_vec)
    }
}