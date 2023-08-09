use core::ops::{Add, Div, Rem, Sub, Mul};
use std::cell;

use rbtree::RBTree;

use revm_primitives::U256;

pub type Uint256 = U256;

pub trait Address {
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
}
pub trait Value {
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Address256 {
    addr: U256,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Value256 {
    value: U256,
}

impl Address for u64 {
    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }
}

impl Value for u64 {
    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }
}

impl Address for Address256 {
    fn is_zero(&self) -> bool {
        self.addr.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { addr: U256::ZERO }
    }
}

impl Value for Value256 {
    fn is_zero(&self) -> bool {
        self.value.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { value: U256::ZERO }
    }
}

impl From<u64> for Address256 {
    fn from(value: u64) -> Self {
        Self {
            addr: U256::from_limbs([0, 0, 0, value]),
        }
    }
}

impl From<u64> for Value256 {
    fn from(value: u64) -> Self {
        Self {
            value: U256::from_limbs([value, 0, 0, 0]),
        }
    }
}

impl From<Vec<u64>> for Value256 {
    fn from(value: Vec<u64>) -> Self {
        Self {
            value: U256::from_limbs([value[0], value[1], value[2], value[3]]),
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

impl Sub for Value256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value - rhs.value,
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

impl Add for Value256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value + rhs.value,
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

impl Div for Value256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value / rhs.value,
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

impl Rem for Value256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value % rhs.value,
        }
    }
}

impl Mul for Value256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value * rhs.value,
        }
    }
}

impl From<Address256> for usize {
    fn from(value: Address256) -> Self {
        value.addr.as_limbs()[3] as usize
    }
}

impl From<Value256> for usize {
    fn from(value: Value256) -> Self {
        value.value.as_limbs()[3] as usize
    }
}

pub trait GenericMemory<K, V> {
    fn new(word_size: u64) -> Self;
    fn compute_address(&self, address: K) -> Vec<K>;
    fn read(&self, address: K) -> Option<&V>;
    fn write(&mut self, address: K, value: V);
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
        + From<u64>
        + Copy
        + PartialEq
        + Add<V, Output = V>
        + Sub<V, Output = V>
        + Rem<V, Output = V>
        + Mul<V, Output = V>
        + Div<V, Output = V>,
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
            self.memory_map.get(&address)
        }
    }

    fn write(&mut self, address: K, value: V) {
        let remain = address % self.cell_size();
        if remain.is_zero() {
            self.memory_map.insert(address, value);
        } else {
            let cell_low = address - remain;
            let cell_high = cell_low + self.cell_size();
            let address_high = address + self.cell_size();
            let mut i = address_high;
            let mut slice = V::from(1);
            let mut offset = V::from(1);
            let base: u64 = 2;
            while i > cell_high {
                i = i - K::from(1);
                slice = slice * V::from(base.pow(8));
            }
            i = address;
            while i < cell_high {
                i = i + K::from(1);
                offset = offset * V::from(base.pow(8));
            }
            let chunk_low_cell = value / slice;
            let chunk_high_cell = (value % slice) * offset;

            // self.memory_map.insert(cell_low, one_v);
            // self.memory_map.insert(cell_high, value);
            // self.memory_map.insert(address, one_v);
            // self.memory_map.insert(address_high, value);
            self.memory_map.insert(cell_low, chunk_low_cell);
            self.memory_map.insert(cell_high, chunk_high_cell);
            //self.memory_map.insert(address + self.cell_size - remain, V::from(mod_chunk));
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
