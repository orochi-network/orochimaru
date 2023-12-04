use crate::base::{Base, B128, B16, B256, B32, B64};
use halo2_proofs::halo2curves::bn256::Fr;

/// Etend Fr field
#[macro_export]
macro_rules! extend_field {
    ($primitive:ident) => {
        impl From<$primitive> for Fr {
            fn from(value: $primitive) -> Self {
                Fr::from_bytes(&value.fixed_le_bytes())
                    .expect("Unable to deserialize Fr from bytes")
            }
        }
    };
}

extend_field!(B256);
extend_field!(B128);
extend_field!(B64);
extend_field!(B32);
extend_field!(B16);
