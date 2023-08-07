use std::ops::{Div, Rem};

use rbtree::RBTree;

use revm_primitives::U256;

pub type Word256 = U256;

pub type Word64 = u64;

pub trait Address<T> {
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Address256 {
    addr: U256,
}

impl Address<U256> for Address256 {
    fn is_zero(&self) -> bool {
        self.addr.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { addr: U256::ZERO }
    }
}

impl From<u64> for Address256 {
    fn from(value: u64) -> Self {
        Self {
            addr: U256::from_limbs([0, 0, 0, value]),
        }
    }
}

impl Div for Address256 {
    type Output = Address256;

    fn div(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr / rhs.addr,
        }
    }
}

impl Rem for Address256 {
    type Output = Address256;

    fn rem(self, rhs: Self) -> Self::Output {
        Self {
            addr: self.addr % rhs.addr,
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
    fn read(&self, address: K) -> Option<&V>;
    fn write(&mut self, address: K, value: V);
    fn cell_size(&self) -> usize;
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
    K: Address<V> + Div + From<u64> + Ord + Into<usize> + Copy,
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
        self.memory_map.get(&address)
    }

    fn write(&mut self, address: K, value: V) {
        self.memory_map.insert(address, value);
    }

    fn len(&self) -> usize {
        self.memory_map.len()
    }

    fn cell_size(&self) -> usize {
        self.cell_size.into()
    }
}
