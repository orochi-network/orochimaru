use crate::{
    base::Base,
    machine::{CellInteraction, Instruction},
};
use ff::Field;
use rand_core::OsRng;
use halo2_proofs::poly::EvaluationDomain;
use halo2_proofs::poly::commitment::{Blind, ParamsProver};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::arithmetic::lagrange_interpolate;
use halo2curves::serde::SerdeObject;
use halo2curves::bn256::{G1, Fr, Bn256};
use rbtree::RBTree;
extern crate alloc;
use alloc::vec::Vec;

/// Generic memory trait, which is implemented by [RawMemory]
/// We realize a memory as a key-value map of address and value
pub trait GenericMemory<K, V, const S: usize> {
    /// Create a new instance of memory
    fn new(cell_size: K) -> Self;
    /// Read a value from a memory address
    /// Return a [CellInteraction](crate::machine::CellInteraction)
    fn read(&mut self, address: K) -> (V, CellInteraction<K, V>);
    /// Write a value to a memory address return a [CellInteraction](crate::machine::CellInteraction)
    fn write(&mut self, address: K, value: V) -> CellInteraction<K, V>;
    /// Get the cell size
    fn cell_size(&self) -> K;
    /// Get the number of cells
    fn len(&self) -> usize;
    /// Commit the polynomial that is interpolated by 
    /// all current memory cells (memory state) as points in Bn256 curve
    fn commit(&self) -> G1;
}

/// [RawMemory] base on [RBTree](rbtree::RBTree)
#[derive(Debug)]
pub struct RawMemory<K, V, const S: usize>
where
    K: Ord,
{
    memory_map: RBTree<K, V>,
    cell_size: K,
    time_log: u64,
    // Secret key used for commitment, 
    kzg_secret_key: Blind<Fr>
}

/// Implementation of [GenericMemory] for [RawMemory]
impl<K, V, const S: usize> GenericMemory<K, V, S> for RawMemory<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    fn new(cell_size: K) -> Self {
        Self {
            memory_map: RBTree::<K, V>::new(),
            cell_size,
            time_log: 0,
            kzg_secret_key: Blind(Fr::random(OsRng))
        }
    }

    fn read(&mut self, address: K) -> (V, CellInteraction<K, V>) {
        let remain = address % self.cell_size();
        if remain.is_zero() {
            // Read on a cell
            let val = self.read_memory(address);
            // Return the tupple of value and interaction
            (
                val,
                CellInteraction::Cell(Instruction::Read(self.increase_time(), address, val)),
            )
        } else {
            // Get the address of 2 cells
            let (addr_lo, addr_hi) = self.compute_address(address, remain);

            // Get the 2 cells
            let val_lo = self.read_memory(addr_lo);
            let val_hi = self.read_memory(addr_hi);
            let cell_size = self.cell_size().to_usize();
            let part_lo = (address - addr_lo).to_usize();
            let part_hi = cell_size - part_lo;
            let mut buf = [0u8; S];

            // Write the value into the buffer
            buf[part_hi..cell_size].copy_from_slice(&val_hi.to_bytes()[0..part_lo]);
            buf[0..part_hi].copy_from_slice(&val_lo.to_bytes()[part_lo..cell_size]);

            // Return the tupple of value and interaction
            (
                V::from_bytes(buf),
                CellInteraction::TwoCell(
                    Instruction::Read(self.increase_time(), addr_lo, val_lo),
                    Instruction::Read(self.increase_time(), addr_hi, val_hi),
                ),
            )
        }
    }

    fn write(&mut self, address: K, value: V) -> CellInteraction<K, V> {
        let remain = address % self.cell_size();
        if remain.is_zero() {
            // Write on a cell
            self.memory_map.insert(address, value);
            CellInteraction::Cell(Instruction::Write(self.increase_time(), address, value))
        } else {
            // Get the address of 2 cells
            let (addr_lo, addr_hi) = self.compute_address(address, remain);
            // Calculate memory address and offset
            let cell_size = self.cell_size().to_usize();
            let part_lo = (address - addr_lo).to_usize();
            let part_hi = cell_size - part_lo;

            let val = value.to_bytes();

            // Write the low part of value to the buffer
            let mut buf = self.read_memory(addr_lo).to_bytes();
            buf[part_lo..cell_size].copy_from_slice(&val[0..part_hi]);
            let val_lo = V::from_bytes(buf);

            // Write the high part of value to the buffer
            let mut buf = self.read_memory(addr_hi).to_bytes();
            buf[0..part_lo].copy_from_slice(&val[part_hi..cell_size]);
            let val_hi = V::from_bytes(buf);

            self.memory_map.replace_or_insert(addr_lo, val_lo);
            self.memory_map.replace_or_insert(addr_hi, val_hi);

            // Return
            CellInteraction::TwoCell(
                Instruction::Write(self.increase_time(), addr_lo, val_lo),
                Instruction::Write(self.increase_time(), addr_hi, val_hi),
            )
        }
    }

    /// Commit the memory current state using KZG with Bn256 curve
    fn commit(&self) -> G1 {

        // Collect the keys and values of the memory
        let mut point_x = Vec::new();
        let mut evals_y: Vec<Fr> = Vec::new();

        for (a, b) in self.memory_map.clone().into_iter() {
            point_x.push(Fr::from_raw_bytes_unchecked(a.to_bytes().as_slice()));
            evals_y.push(Fr::from_raw_bytes_unchecked(b.to_bytes().as_slice()));
        }

        // Since we will work with polynomials with degree t = 2^k, we need to raise
        // the polynomial degree.

        // Use Lagrange interpolation to find the state polynomial
        let state_poly = lagrange_interpolate(
            point_x.as_slice(), 
            evals_y.as_slice());
        
        // Params setup 
        let k: u32 = S.try_into().unwrap();
        let params = ParamsKZG::<Bn256>::new(k);
        let domain = EvaluationDomain::new(1, k);

        let poly = domain.coeff_from_vec(state_poly);

        params.commit(&poly, self.kzg_secret_key)
    }

    fn len(&self) -> usize {
        self.memory_map.len()
    }

    fn cell_size(&self) -> K {
        self.cell_size
    }
}

impl<K, V, const S: usize> RawMemory<K, V, S>
where
    K: Base<S>,
    V: Base<S>,
{
    fn increase_time(&mut self) -> u64 {
        self.time_log += 1;
        self.time_log
    }

    fn compute_address(&self, address: K, remain: K) -> (K, K) {
        let base = address - remain;
        (base, base + self.cell_size)
    }

    fn read_memory(&self, address: K) -> V {
        match self.memory_map.get(&address) {
            Some(r) => r.clone(),
            None => V::zero(),
        }
    }
}
