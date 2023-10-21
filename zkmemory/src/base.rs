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

/// Convert from/to [usize](core::usize)
pub trait UsizeConvertible {
    /// Convert from [usize](core::usize)
    fn from_usize(value: usize) -> Self;
    /// Convert to [usize](core::usize)
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

macro_rules! new_base {
    ($primitive:ident, $byte_size: expr) => {
        impl UsizeConvertible for $primitive {
            fn from_usize(value: usize) -> Self {
                value as $primitive
            }

            fn to_usize(&self) -> usize {
                *self as usize
            }
        }

        impl Base<$byte_size> for $primitive {
            const MAX: Self = $primitive::MAX;

            const MIN: Self = $primitive::MIN;

            fn is_zero(&self) -> bool {
                *self == 0
            }

            fn zero() -> Self {
                0
            }

            fn to_bytes(&self) -> [u8; $byte_size] {
                self.to_be_bytes()
            }

            fn from_bytes(bytes: [u8; $byte_size]) -> Self {
                Self::from_be_bytes(bytes)
            }
        }
    };
}

new_base!(u64, 8);
new_base!(u32, 4);
new_base!(u16, 2);
