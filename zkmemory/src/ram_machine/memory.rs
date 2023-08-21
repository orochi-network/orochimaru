use crate::machine::{CellInteraction, Instruction};
use core::ops::{Add, Div, Rem, Sub};
use rbtree::RBTree;
use revm_primitives::U256;

/// Base trait for memory address and value
pub trait Base<const S: usize, K = Self>:
    Ord
    + Copy
    + PartialEq
    + Add<K, Output = K>
    + Sub<K, Output = K>
    + Rem<K, Output = K>
    + Div<K, Output = K>
{
    /// Check if the value is zero
    fn is_zero(&self) -> bool;
    /// Get the zero value
    fn zero() -> Self;
    /// Convert to Vec<u8> (bytes)
    fn to_bytes_be(&self) -> [u8; S];
    /// Convert from bytes
    fn from_bytes_be(chunk: [u8; S]) -> Self;
    /// Convert from [usize]
    fn from_usize(value: usize) -> Self;
    /// Convert to [usize]
    fn to_usize(&self) -> usize;
}

/// Generic memory trait
pub trait GenericMemory<const S: usize, K, V> {
    /// Create a new instance of memory
    fn new(word_size: usize) -> Self;
    /// Read a value from a memory address
    /// Return a [CellInteraction](crate::machine::CellInteraction)
    fn read(&mut self, address: K) -> (V, CellInteraction<K, V>);
    /// Write a value to a memory address return a [CellInteraction](crate::machine::CellInteraction)
    fn write(&mut self, address: K, value: V) -> CellInteraction<K, V>;
    /// Get the cell size
    fn cell_size(&self) -> K;
    /// Get the number of cells
    fn len(&self) -> usize;
}

/// 256 bits unsigned integer
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Uint256 {
    val: U256,
}

impl Base<32> for Uint256 {
    fn is_zero(&self) -> bool {
        self.val.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { val: U256::ZERO }
    }

    fn to_bytes_be(&self) -> [u8; 32] {
        self.val.to_be_bytes()
    }

    fn from_bytes_be(chunk: [u8; 32]) -> Self {
        Self {
            val: U256::from_be_bytes(chunk),
        }
    }

    fn from_usize(value: usize) -> Self {
        Self {
            val: U256::from_limbs([value as u64, 0, 0, 0]),
        }
    }

    fn to_usize(&self) -> usize {
        self.val.as_limbs()[0] as usize
    }
}

impl Sub for Uint256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val - rhs.val,
        }
    }
}

impl Add for Uint256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val + rhs.val,
        }
    }
}

impl Div for Uint256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val / rhs.val,
        }
    }
}

impl Rem for Uint256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self {
            val: self.val % rhs.val,
        }
    }
}

impl Base<8> for u64 {
    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }

    fn to_bytes_be(&self) -> [u8; 8] {
        self.to_be_bytes()
    }

    fn from_bytes_be(chunk: [u8; 8]) -> Self {
        u64::from_be_bytes(chunk)
    }

    fn from_usize(value: usize) -> Self {
        value as u64
    }

    fn to_usize(&self) -> usize {
        *self as usize
    }
}

impl Base<4> for u32 {
    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }

    fn to_bytes_be(&self) -> [u8; 4] {
        self.to_be_bytes()
    }

    fn from_bytes_be(chunk: [u8; 4]) -> Self {
        u32::from_be_bytes(chunk)
    }

    fn from_usize(value: usize) -> Self {
        value as u32
    }

    fn to_usize(&self) -> usize {
        *self as usize
    }
}

/// Raw memory
#[derive(Debug)]
pub struct RawMemory<const S: usize, K, V>
where
    K: Ord,
{
    memory_map: RBTree<K, V>,
    cell_size: K,
    time_log: u64,
}

/// Implementation of [GenericMemory] for [RawMemory]
impl<const S: usize, K, V> GenericMemory<S, K, V> for RawMemory<S, K, V>
where
    K: Base<S>,
    V: Base<S>,
{
    fn new(word_size: usize) -> Self {
        if word_size % 8 != 0 {
            panic!("Word size is calculated in bits so it must be divied by 8")
        }
        Self {
            memory_map: RBTree::<K, V>::new(),
            cell_size: K::from_usize(word_size / 8),
            time_log: 0,
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
            buf[part_lo..cell_size].copy_from_slice(&val_lo.to_bytes_be()[part_lo..cell_size]);
            buf[0..part_hi].copy_from_slice(&val_lo.to_bytes_be()[0..part_hi]);

            // Return the tupple of value and interaction
            (
                V::from_bytes_be(buf),
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

            let val = value.to_bytes_be();

            // Write the low part of value to the buffer
            let mut buf = self.read_memory(addr_lo).to_bytes_be();
            buf[part_lo..cell_size].copy_from_slice(&val[part_lo..cell_size]);
            let val_lo = V::from_bytes_be(buf);

            // Write the high part of value to the buffer
            let mut buf = self.read_memory(addr_hi).to_bytes_be();
            buf[0..part_hi].copy_from_slice(&val[0..part_hi]);
            let val_hi = V::from_bytes_be(buf);

            self.memory_map.replace_or_insert(addr_lo, val_lo);
            self.memory_map.replace_or_insert(addr_hi, val_hi);

            // Return
            CellInteraction::TwoCell(
                Instruction::Write(self.increase_time(), addr_lo, val_lo),
                Instruction::Write(self.increase_time(), addr_hi, val_hi),
            )
        }
    }

    fn len(&self) -> usize {
        self.memory_map.len()
    }

    fn cell_size(&self) -> K {
        self.cell_size
    }
}

impl<const S: usize, K, V> RawMemory<S, K, V>
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
