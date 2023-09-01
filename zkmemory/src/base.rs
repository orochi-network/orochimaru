use core::fmt::{Debug, Display};
use core::ops::{Add, Div, Mul, Rem, Sub};
use core::usize;
use ethnum::AsU256;
pub use ethnum::U256;

/// Base trait for memory address and value
pub trait Base<const S: usize, T = Self>:
    Ord
    + Copy
    + PartialEq
    + UsizeConvertible
    + Display
    + Debug
    + Add<T, Output = T>
    + Mul<T, Output = T>
    + Sub<T, Output = T>
    + Rem<T, Output = T>
    + Div<T, Output = T>
{
    /// The max value of the cell
    const MAX: Self;
    /// The min value of the cell
    const MIN: Self;
    /// The size of the cell
    const CELL_SIZE: usize = S;
    /// Check if the value is zero
    fn is_zero(&self) -> bool;
    /// Get the zero value
    fn zero() -> Self;
    /// Convert to big endian bytes
    fn to_bytes(&self) -> [u8; S];
    /// Convert from big endian bytes
    fn from_bytes(bytes: [u8; S]) -> Self;
}

/// Convert from/to [usize]
pub trait UsizeConvertible {
    /// Convert from [usize]
    fn from_usize(value: usize) -> Self;
    /// Convert to [usize]
    fn to_usize(&self) -> usize;
}

impl UsizeConvertible for U256 {
    fn from_usize(value: usize) -> Self {
        value.as_u256()
    }

    fn to_usize(&self) -> usize {
        self.as_usize()
    }
}

impl Base<32> for U256 {
    const MAX: Self = U256::MAX;

    const MIN: Self = U256::MIN;

    fn is_zero(&self) -> bool {
        self.eq(&U256::ZERO)
    }

    fn zero() -> Self {
        U256::ZERO
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_be_bytes(bytes)
    }
}

impl UsizeConvertible for u64 {
    fn from_usize(value: usize) -> Self {
        value as u64
    }

    fn to_usize(&self) -> usize {
        *self as usize
    }
}

impl Base<8> for u64 {
    const MAX: Self = u64::MAX;

    const MIN: Self = u64::MIN;

    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }

    fn to_bytes(&self) -> [u8; 8] {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: [u8; 8]) -> Self {
        Self::from_be_bytes(bytes)
    }
}

impl UsizeConvertible for u32 {
    fn from_usize(value: usize) -> Self {
        value as u32
    }

    fn to_usize(&self) -> usize {
        *self as usize
    }
}

impl Base<4> for u32 {
    const MAX: Self = u32::MAX;

    const MIN: Self = u32::MIN;

    fn is_zero(&self) -> bool {
        *self == 0
    }

    fn zero() -> Self {
        0
    }

    fn to_bytes(&self) -> [u8; 4] {
        self.to_be_bytes()
    }

    fn from_bytes(bytes: [u8; 4]) -> Self {
        Self::from_be_bytes(bytes)
    }
}
