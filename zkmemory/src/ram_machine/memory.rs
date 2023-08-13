use crate::machine::{CellInteraction, Instruction};
use core::ops::{Add, Div, Rem, Sub};
use rbtree::RBTree;

use revm_primitives::U256;

pub trait Base<K = Self>:
    Ord
    + From<u64>
    + Copy
    + PartialEq
    + Add<K, Output = K>
    + Sub<K, Output = K>
    + Rem<K, Output = K>
    + Div<K, Output = K>
{
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
}

pub trait GenericMemory<K, V> {
    fn new(word_size: u64) -> Self;
    fn compute_address(&self, address: K) -> Vec<K>;
    fn read(&mut self, address: K) -> CellInteraction<K, V>;
    fn write(&mut self, address: K, value: V) -> CellInteraction<K, V>;
    fn increase_time(&mut self) -> u64;
    fn cell_size(&self) -> K;
    fn len(&self) -> usize;
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Uint256 {
    addr: U256,
}

impl Base for Uint256 {
    fn is_zero(&self) -> bool {
        self.addr.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { addr: U256::ZERO }
    }
}

impl From<u64> for Uint256 {
    fn from(value: u64) -> Self {
        Self {
            addr: U256::from_limbs([0, 0, 0, value]),
        }
    }
}

impl Sub for Uint256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr - rhs.addr,
        }
    }
}

impl Add for Uint256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr + rhs.addr,
        }
    }
}

impl Div for Uint256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr / rhs.addr,
        }
    }
}

impl Rem for Uint256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr % rhs.addr,
        }
    }
}

impl From<Uint256> for usize {
    fn from(value: Uint256) -> Self {
        value.addr.as_limbs()[3] as usize
    }
}

impl Base for u64 {
    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }
}

#[derive(Debug)]
pub struct RawMemory<K, V>
where
    K: Ord,
{
    memory_map: RBTree<K, V>,
    cell_size: K,
    time_log: u64,
}

impl<K, V> GenericMemory<K, V> for RawMemory<K, V>
where
    K: Base,
    V: Base,
{
    fn new(word_size: u64) -> Self {
        if word_size % 8 != 0 {
            panic!("Word size is calculated in bits so it must be divied by 8")
        }
        Self {
            memory_map: RBTree::<K, V>::new(),
            cell_size: K::from(word_size / 8),
            time_log: 0,
        }
    }

    fn increase_time(&mut self) -> u64 {
        self.time_log += 1;
        self.time_log
    }

    fn read(&mut self, address: K) -> CellInteraction<K, V> {
        let remain = address % self.cell_size();
        let e = K::from(0);
        if remain.is_zero() {
            // Read on a cell
            //self.memory_map.get(&address);
            CellInteraction::Cell(Instruction::Read(self.increase_time(), address, V::zero()))
        } else {
            CellInteraction::TwoCell(
                Instruction::Read(self.increase_time(), address, V::zero()),
                Instruction::Read(self.increase_time(), address, V::zero()),
            )
            // Read on the middle of the cell
            /*
            // Attempt to read 2 cells, low and high, then combine and return
            self.memory_map.get(&address);
            let cell_low = address - remain;
            let cell_high = cell_low + self.cell_size();
            let chunk_low_cell = self.memory_map.get(&cell_low);
            let chunk_high_cell = self.memory_map.get(&cell_high);
            match (chunk_low_cell, chunk_high_cell) {
                (Some(chunk_low), Some(chunk_high)) => {
                    // returns a value referencing data owned by the current function
                    let result = V::from(vec![0u64, 1u64, 2u64, 3u64]);
                    Some(&result)
                }

                (Some(chunk_low), None) => {
                    // returns a value referencing data owned by the current function
                    let result = V::from(vec![0u64, 1u64, 2u64, 3u64]);
                    Some(&result)
                }

                (None, Some(chunk_high)) => {
                    // returns a value referencing data owned by the current function
                    let result = V::from(vec![0u64, 1u64, 2u64, 3u64]);
                    Some(&result)
                }

                (None, None) => None,
            }*/
        }
    }

    fn write(&mut self, address: K, value: V) -> CellInteraction<K, V> {
        let remain = address % self.cell_size();
        if remain.is_zero() {
            self.memory_map.insert(address, value);
            CellInteraction::Cell(Instruction::Write(self.increase_time(), address, value))
        } else {
            CellInteraction::TwoCell(
                Instruction::Write(self.increase_time(), address, value),
                Instruction::Write(self.increase_time(), address, value),
            )
            /*
                       let chunk = value.to_bytes_le();
                       let cell_low = address - remain;
                       let cell_high = cell_low + self.cell_size();
                       let offset = (cell_high - address)

                       let chunk_low_cell = V::from(convert_to_u64(Vec::from(&chunk[0..offset as usize])));
                       let chunk_high_cell = V::from(convert_to_u64(Vec::from(
                           &chunk[offset as usize..self.cell_size() as usize],
                       )));

                       self.memory_map.insert(cell_low, chunk_low_cell);
                       self.memory_map.insert(cell_high, chunk_high_cell);
            */
        }
    }

    fn len(&self) -> usize {
        self.memory_map.len()
    }

    fn cell_size(&self) -> K {
        self.cell_size
    }

    fn compute_address(&self, address: K) -> Vec<K> {
        let remain = address % self.cell_size;
        if remain.is_zero() {
            vec![address]
        } else {
            let base = address - remain;
            vec![base, base + self.cell_size]
        }
    }
}
