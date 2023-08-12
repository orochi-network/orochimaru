use core::ops::{Add, Div, Rem, Sub, Mul};
use std::cell;
use rbtree::RBTree;

use revm_primitives::U256;

pub type Uint256 = U256;

pub trait Address {
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
    fn to_u64(&self) -> u64;
}
pub trait Value {
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
    fn to_bytes_le(&self) -> Vec<u8>;
    fn from_bytes(chunk: Vec<u8>) -> Self;
}

// pub trait Zeroable {
//     fn is_zero(&self) -> bool;
//     fn zero() -> Self;
// }

// pub trait Computable<K = Self>:
//     Ord
//     + From<u64>
//     + Copy
//     + PartialEq
//     + Add<K, Output = K>
//     + Sub<K, Output = K>
//     + Rem<K, Output = K>
//     + Div<K, Output = K>
// {}

// pub trait Address: Computable + Zeroable {}
// pub trait Value: Computable + Zeroable {
//     fn to_bytes_le(&self) -> Vec<u8>;
//     fn from_bytes(chunk: Vec<u8>) -> Self;
// }

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Address256 {
    addr: U256,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Value256 {
    inner: U256,
}

// A function converting Vec<u8> to Vec<u64>
fn convert_to_u64(input: Vec<u8>) -> Vec<u64> {
    let mut result = Vec::with_capacity(4);
    let mut current_value: u64 = 0;
    let mut shift = 0;

    for &byte in &input {
        current_value |= (byte as u64) << shift;
        shift += 8;

        if shift == 64 {
            result.push(current_value);
            current_value = 0;
            shift = 0;
        }
    }

    if shift > 0 {
        result.push(current_value);
    }

    // Pad with zeros if needed
    while result.len() < 4 {
        result.push(0);
    }

    result
}

impl Value for Value256 {
    fn is_zero(&self) -> bool {
        self.inner.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { inner: U256::ZERO }
    }

    fn to_bytes_le(&self) -> Vec<u8> {
        Vec::from(self.inner.as_le_bytes())
    }

    fn from_bytes(chunk: Vec<u8>) -> Self {
        Self {
            inner : U256::from_limbs(convert_to_u64(chunk).try_into().unwrap())
        }
    }
}

impl Address for Address256 {
    fn is_zero(&self) -> bool {
        self.addr.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { addr: U256::ZERO }
    }

    fn to_u64(&self) -> u64 {
        self.addr.as_limbs()[3] as u64
    }
}


impl From<u64> for Address256 {
    fn from(value: u64) -> Self {
        Self {
            addr: U256::from_limbs([0, 0, 0, value]),
        }
    }
}

impl From<Vec<u64>> for Value256 {
    fn from(value: Vec<u64>) -> Self {
        Self {
            inner: U256::from_limbs([value[0], value[1], value[2], value[3]]),
        }
    }
}


impl Sub for Address256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr - rhs.addr,
        }
    }
}

impl Add for Address256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr + rhs.addr,
        }
    }
}

impl Div for Address256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr / rhs.addr,
        }
    }
}

impl Rem for Address256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr % rhs.addr,
        }
    }
}

impl Add for Value256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
        }
    }
}

impl Sub for Value256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner - rhs.inner,
        }
    }
}

impl Mul for Value256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
        }
    }
}

impl From<Address256> for usize {
    fn from(value: Address256) -> Self {
        value.addr.as_limbs()[3] as usize
    }
}

pub trait GenericMemory<K, V> {
    fn new(word_size: u64) -> Self;
    fn compute_address(&self, address: K) -> Vec<K>;
    fn read(&self, address: K) -> Option<&V>;
    fn write(&mut self, address: K, value: V) -> u64;
    fn cell_size(&self) -> K;
    fn len(&self) -> usize;
}

pub struct RawMemory<K, V>
where
    K: Ord,
{
    memory_map: RBTree<K, V>,
    cell_size: K,
}

impl<K, V> GenericMemory<K, V> for RawMemory<K, V>
where
    K: Address
        + Ord
        + From<u64>
        + Copy
        + PartialEq
        + Add<K, Output = K>
        + Sub<K, Output = K>
        + Rem<K, Output = K>
        + Div<K, Output = K>,
    V: Value
        + Ord
        + From<Vec<u64>>
        + Copy
        + PartialEq
        + Add<V, Output = V>
        + Sub<V, Output = V>
        + Mul<V, Output = V>
{
    fn new(word_size: u64) -> Self {
        if word_size % 8 != 0 {
            panic!("Word size is calculated in bits so it must be divied by 8")
        }
        Self {
            memory_map: RBTree::<K, V>::new(),
            cell_size: K::from(word_size / 8),
        }
    }

    fn read(&self, address: K) -> Option<&V> {
        let remain = address % self.cell_size();
        if remain.is_zero() {
            // Read on a cell
            self.memory_map.get(&address)
        } else {
            // Read on the middle of the cell

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
                },

                (Some(chunk_low), None) => {
                    // returns a value referencing data owned by the current function
                    let result = V::from(vec![0u64, 1u64, 2u64, 3u64]);
                    Some(&result)
                },

                (None, Some(chunk_high)) => {
                    // returns a value referencing data owned by the current function
                    let result = V::from(vec![0u64, 1u64, 2u64, 3u64]);
                    Some(&result)
                },

                (None, None) => None,
            }
        }
    }

    fn write(&mut self, address: K, value: V) -> u64{
        let remain = address % self.cell_size();
        if remain.is_zero() {
            self.memory_map.insert(address, value);
            return 0;

        } else {

            let chunk = value.to_bytes_le();
            let cell_low = address - remain;
            let cell_high = cell_low + self.cell_size();
            let offset = (cell_high - address).to_u64();
            
            let chunk_low_cell = V::from(convert_to_u64(Vec::from(&chunk[0..offset as usize])));
            let chunk_high_cell = V::from(convert_to_u64(Vec::from(&chunk[offset as usize..self.cell_size().to_u64() as usize])));

            self.memory_map.insert(cell_low, chunk_low_cell);
            self.memory_map.insert(cell_high, chunk_high_cell);

            return 1;
        };
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
