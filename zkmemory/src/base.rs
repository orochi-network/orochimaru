use core::fmt::{Debug, Display};
use core::ops::{Add, Div, Mul, Rem, Sub};
use core::usize;
use ethnum::U256;

/// Base trait for memory address and value
pub trait Base<const S: usize, T = Self>:
    Ord
    + Copy
    + PartialEq
    + Eq
    + Ord
    + PartialOrd
    + Display
    + Debug
    + From<i32>
    + Into<i32>
    + From<usize>
    + Into<usize>
    + From<u64>
    + Into<u64>
    + From<[u8; S]>
    + Into<[u8; S]>
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
    /// Cell size in Base
    const WORD_SIZE: Self;
    /// The size of the cell
    const WORD_USIZE: usize = S;
    /// Check if the value is zero
    fn is_zero(&self) -> bool;
    /// Get the zero value
    fn zero() -> Self;
    /// Fill to 32 bytes from any bases
    /// that are less than 32 bytes in raw bytes representation
    fn zfill32(&self) -> [u8; 32];
}

/// Convert from/to [usize](core::usize)
pub trait UIntConvertible {
    /// Convert from [usize](core::usize)
    fn from_usize(value: usize) -> Self;
    /// Convert to [usize](core::usize)
    fn to_usize(&self) -> usize;
}

/// Uint256 is a wrapper of [U256](ethnum::U256) to implement [Base](crate::base::Base)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Uint<T>(T);

impl<T: Display> Display for Uint<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<T: Div<Output = T>> Div for Uint<T> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0 / rhs.0)
    }
}

impl<T: Add<Output = T>> Add for Uint<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<T: Sub<Output = T>> Sub for Uint<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<T: Rem<Output = T>> Rem for Uint<T> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.0 % rhs.0)
    }
}

impl<T: Mul<Output = T>> Mul for Uint<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

macro_rules! new_base {
    (U256, $byte_size: expr) => {
        impl Base<$byte_size> for Uint<U256> {
            const MAX: Self = Self(U256::MAX);

            const MIN: Self = Self(U256::MIN);

            const WORD_SIZE: Self = Self(U256::new($byte_size));

            fn is_zero(&self) -> bool {
                self.0 == U256::ZERO
            }

            fn zero() -> Self {
                Self(U256::ZERO)
            }

            fn zfill32(&self) -> [u8; 32] {
                self.0.to_be_bytes()
            }
        }

        impl From<i32> for Uint<U256> {
            fn from(value: i32) -> Self {
                Self(U256::new(value as u128))
            }
        }

        impl From<usize> for Uint<U256> {
            fn from(value: usize) -> Self {
                Self(U256::new(value as u128))
            }
        }

        impl From<u64> for Uint<U256> {
            fn from(value: u64) -> Self {
                Self(U256::new(value as u128))
            }
        }

        impl From<Uint<U256>> for i32 {
            fn from(value: Uint<U256>) -> Self {
                value.0.as_i32()
            }
        }

        impl From<Uint<U256>> for usize {
            fn from(value: Uint<U256>) -> Self {
                value.0.as_usize()
            }
        }

        impl From<Uint<U256>> for u64 {
            fn from(value: Uint<U256>) -> Self {
                value.0.as_u64()
            }
        }

        impl From<Uint<U256>> for [u8; $byte_size] {
            fn from(value: Uint<U256>) -> Self {
                value.0.to_be_bytes()
            }
        }

        impl From<[u8; $byte_size]> for Uint<U256> {
            fn from(value: [u8; $byte_size]) -> Self {
                Self(U256::from_be_bytes(value))
            }
        }
    };
    ($primitive:ident, $byte_size: expr) => {
        impl Base<$byte_size> for Uint<$primitive> {
            const MAX: Self = Self($primitive::MAX);

            const MIN: Self = Self($primitive::MIN);

            const WORD_SIZE: Self = Self($byte_size as $primitive);

            fn is_zero(&self) -> bool {
                self.0 == 0
            }

            fn zero() -> Self {
                Self(0)
            }

            fn zfill32(&self) -> [u8; 32] {
                let bytes = self.0.to_be_bytes();
                let mut buffer = [0u8; 32];
                buffer[(32 - $byte_size)..].copy_from_slice(&bytes);
                buffer
            }
        }

        impl From<i32> for Uint<$primitive> {
            fn from(value: i32) -> Self {
                Self(value as $primitive)
            }
        }

        impl From<usize> for Uint<$primitive> {
            fn from(value: usize) -> Self {
                Self(value as $primitive)
            }
        }

        impl From<u64> for Uint<$primitive> {
            fn from(value: u64) -> Self {
                Self(value as $primitive)
            }
        }

        impl From<Uint<$primitive>> for i32 {
            fn from(value: Uint<$primitive>) -> Self {
                value.0 as i32
            }
        }

        impl From<Uint<$primitive>> for usize {
            fn from(value: Uint<$primitive>) -> Self {
                value.0 as usize
            }
        }

        impl From<Uint<$primitive>> for u64 {
            fn from(value: Uint<$primitive>) -> Self {
                value.0 as u64
            }
        }

        impl From<Uint<$primitive>> for [u8; $byte_size] {
            fn from(value: Uint<$primitive>) -> Self {
                value.0.to_be_bytes()
            }
        }

        impl From<[u8; $byte_size]> for Uint<$primitive> {
            fn from(value: [u8; $byte_size]) -> Self {
                Self($primitive::from_be_bytes(value))
            }
        }
    };
}

new_base!(U256, 32);
new_base!(u128, 16);
new_base!(u64, 8);
new_base!(u32, 4);
new_base!(u16, 2);

/// Uint256 is a wrapper of [U256](ethnum::U256) to implement [Base](crate::base::Base)
pub type B256 = Uint<U256>;
/// Uint128 is a wrapper of [u128](core::u128) to implement [Base](crate::base::Base)
pub type B128 = Uint<u128>;
/// Uint64 is a wrapper of [u64](core::u64) to implement [Base](crate::base::Base)
pub type B64 = Uint<u64>;
/// Uint32 is a wrapper of [u32](core::u32) to implement [Base](crate::base::Base)
pub type B32 = Uint<u32>;
/// Uint16 is a wrapper of [u16](core::u16) to implement [Base](crate::base::Base)
pub type B16 = Uint<u16>;
