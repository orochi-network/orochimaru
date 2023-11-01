use halo2_proofs::arithmetic::{lagrange_interpolate, best_multiexp};
use halo2_proofs::poly::{EvaluationDomain, Polynomial, Coeff};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2curves::bn256::{Bn256, Fr, G1, G1Affine};
use crate::base::Base;
use crate::machine::AbstractMemoryMachine;
use crate::state_machine::StateMachine;
extern crate alloc;
use alloc::vec::Vec;


/// A KZG Module using curve Bn256
#[derive(Debug)]
pub struct KZGMemoryCommitment<K, V, const S: usize, const T: usize>
where 
    K: Base<S>,
    V: Base<T>,
{
    domain: EvaluationDomain<Fr>,
    machine: StateMachine<K, V, S, T>,
    common_reference_string: Vec<G1Affine>,
}

impl<K, V, const S: usize, const T: usize> KZGMemoryCommitment<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Init - use Bn256 curve and evaluation domain Fr
    pub fn init(k: u32, machine: StateMachine<K, V, S, T>) -> Self {
        let params = ParamsKZG::<Bn256>::new(k);
        let crs = Vec::from(params.get_g());

        Self {
            domain: EvaluationDomain::new(1, k),
            machine: machine,
            common_reference_string: crs,
        }
    }

    /// Get all cells from the memory section 
    pub fn get_cells(&mut self) -> Vec<(K, V)> {
        self.machine.get_memory_cells()
    }

    /// Commit to a polynomial, the result is in G1
    pub fn commit_polynomial_in_g1(&self, poly: Polynomial<Fr, Coeff>) -> G1 {
        let mut scalars = Vec::with_capacity(poly.len());
        scalars.extend(poly.iter());
        let bases = &self.common_reference_string;
        let size = scalars.len();
        assert!(bases.len() >= size);
        best_multiexp(&scalars, &bases[0..size])
    }

    /// Convert points of type Base<S> to Fr element
    fn base_to_field_elements(&self, points: Vec<(K, V)>) -> Vec<(Fr, Fr)> {
        let mut field_point_vec: Vec<(Fr, Fr)> = Vec::new();
        for (point, value) in points.into_iter() {
            field_point_vec.push((
                self.be_bytes_to_field(point.zfill32().as_mut_slice()), 
                self.be_bytes_to_field(value.zfill32().as_mut_slice())));
        }
        field_point_vec
    }

    /// Convert raw bytes from big endian to Fr element
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner =
        [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }

    /// Use lagrange interpolation to form a polynomial from points
    fn lagrange_from_points(&self, points: Vec<(Fr, Fr)>) -> Polynomial<Fr, Coeff> {
        let point: Vec<Fr> = points.iter().map(|&(a, _)| a).collect();
        let value: Vec<Fr> = points.iter().map(|&(_, b)| b).collect();
        let poly_coefficients = lagrange_interpolate(&point, &value);
        self.domain.coeff_from_vec(poly_coefficients)
    }

    /// Commit the memory state
    pub fn commit_memory_state(&mut self) -> G1 {
        let cells = self.get_cells();
        let points_vec = self.base_to_field_elements(cells);
        let state_poly = self.lagrange_from_points(points_vec);
        let commitment = self.commit_polynomial_in_g1(state_poly);
        commitment
    }

    /// Get the memory state represented as a polynomial
    pub fn get_poly_state(&mut self) -> Polynomial<Fr, Coeff> {
        let cells = self.get_cells();
        let points_vec = self.base_to_field_elements(cells);
        self.lagrange_from_points(points_vec)
    }

    /// Verify the polynomial state is valid
    pub fn verify_poly(&mut self, commitment: G1) -> bool {
        let state_commitment = self.commit_memory_state();
        state_commitment == commitment
    }
}