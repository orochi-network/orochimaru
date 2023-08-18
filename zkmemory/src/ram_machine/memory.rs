use crate::machine::{CellInteraction, Instruction};
use core::ops::{Add, Div, Rem, Sub};
use rbtree::RBTree;
use revm_primitives::U256;

/// Base trait for memory address and value
pub trait Base<K = Self>:
    Ord
    + Copy
    + PartialEq
    + From<u64>
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
    fn to_bytes_be(&self) -> Vec<u8>;
    /// Convert from bytes
    fn from_bytes_be(chunk: Vec<u8>) -> Self;
}

/// Generic memory trait
pub trait GenericMemory<K, V> {
    /// Create a new instance of memory
    fn new(word_size: u64) -> Self;
    /// Read a value from a memory address
    /// Return a [CellInteraction](crate::machine::CellInteraction)
    fn read(&mut self, address: K) -> CellInteraction<K, V>;
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
    addr: U256,
}

impl Base for Uint256 {
    fn is_zero(&self) -> bool {
        self.addr.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        Self { addr: U256::ZERO }
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.addr.to_be_bytes_vec()
    }

    fn from_bytes_be(chunk: Vec<u8>) -> Self {
        let chunk_bytes: [u8; 32] = chunk.try_into().unwrap();
        Self { addr: U256::from_be_bytes(chunk_bytes)}
    }
}

impl From<u64> for Uint256 {
    fn from(value: u64) -> Self {
        Self {
            // Little-endian style
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

    fn to_bytes_be(&self) -> Vec<u8> {
        Vec::from(self.to_be_bytes())
    }

    fn from_bytes_be(chunk: Vec<u8>) -> Self {
        u64::from_be_bytes(chunk.clone().try_into().unwrap())
    }
}

/// Raw memory
#[derive(Debug)]
pub struct RawMemory<K, V>
where
    K: Ord,
{
    memory_map: RBTree<K, V>,
    cell_size: K,
    time_log: u64,
}

/// Implementation of [GenericMemory] for [RawMemory]
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

    fn read(&mut self, address: K) -> CellInteraction<K, V> {
        let remain = address % self.cell_size();
        if remain.is_zero() {

            // Read on a cell
            let chunk = self.memory_map.get(&address);

            match chunk {
                Some(result) => {

                    // Avoid the error of using a borrowed variable
                    let temp = V::from_bytes_be(result.to_bytes_be());
                    CellInteraction::Cell(Instruction::Read(self.increase_time(), address, temp))
                },

                // By default, unwritten cell is 0
                None => CellInteraction::Cell(Instruction::Read(self.increase_time(), address, V::from(0))),
            } 
            
        } else {

            // Get the address of 2 cells
            let cell_address = self.compute_address(address);
            let cell_low = cell_address[0];
            let cell_high = cell_address[1];

            // Get the 2 cells
            let data_cell_low = self.memory_map.get(&cell_low);
            let data_cell_high = self.memory_map.get(&cell_high);

            match (data_cell_low, data_cell_high) {

                // Both cells are written
                (Some(chunk_low), Some(chunk_high)) => {
        
                    let chunk_low_bytes = V::from_bytes_be(chunk_low.to_bytes_be());
                    let chunk_high_bytes = V::from_bytes_be(chunk_high.to_bytes_be());

                    CellInteraction::TwoCell(
                        Instruction::Read(self.increase_time(), cell_low, chunk_low_bytes),
                        Instruction::Read(self.increase_time(), cell_high, chunk_high_bytes),
                    )
                },

                // Chunk high is unwritten
                (Some(chunk_low), None) => {

                    let chunk_low_bytes = V::from_bytes_be(chunk_low.to_bytes_be());

                    CellInteraction::TwoCell(
                        Instruction::Read(self.increase_time(), cell_low, chunk_low_bytes),
                        Instruction::Read(self.increase_time(), cell_high, V::from(0)),
                    )
                },

                // Chunk low is unwritten
                (None, Some(chunk_high)) => {
                    let chunk_high_bytes = V::from_bytes_be(chunk_high.to_bytes_be());
                    CellInteraction::TwoCell(
                        Instruction::Read(self.increase_time(), cell_low, V::from(0)),
                        Instruction::Read(self.increase_time(), cell_high, chunk_high_bytes),
                    )
                },

                // Both cells are unwritten
                (None, None) => {
                    CellInteraction::TwoCell(
                        Instruction::Read(self.increase_time(), cell_low, V::from(0)),
                        Instruction::Read(self.increase_time(), cell_high, V::from(0)),
                    )
                },
            }
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
            let cell_address = self.compute_address(address);
            let cell_low = cell_address[0];
            let cell_high = cell_address[1];

            // slice : the distance from cell_high to address
            let mut slice = cell_high - address;

            // Convert the value into bytes chunk
            let chunk = value.to_bytes_be();

            // Find the offset i that divides 2 cells
            let mut i: usize = 0;
            while !slice.is_zero() {
                slice = slice - K::from(1);
                i += 1;
            }

            // Get the cell size in usize
            let cell_size = self.cell_size().to_bytes_be().len();

            // Slice 2 cells into low and high
            let mut chunk_low = Vec::from(&chunk[0..i]);
            let mut chunk_high = Vec::from(&chunk[i..cell_size]);

            // Append chunk in high cell with 0
            while chunk_high.len() < cell_size {
                chunk_high.push(0);
            }

            // Prepend chunk in low cell with 0
            while chunk_low.len() < cell_size {
                chunk_low.insert(0 as usize, 0u8);
            }

            // Create write cell from the 2 chunks
            let cell_low_result = V::from_bytes_be(chunk_low);
            let cell_high_result = V::from_bytes_be(chunk_high);

            // Write
            self.memory_map.insert(cell_low, cell_low_result);
            self.memory_map.insert(cell_high, cell_high_result);

            // Return
            CellInteraction::TwoCell(
                Instruction::Write(self.increase_time(), cell_low, cell_low_result),
                Instruction::Write(self.increase_time(), cell_high, cell_high_result),
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

impl<K, V> RawMemory<K, V>
where
    K: Base,
    V: Base,
{
    fn increase_time(&mut self) -> u64 {
        self.time_log += 1;
        self.time_log
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
