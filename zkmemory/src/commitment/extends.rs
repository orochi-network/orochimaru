use crate::base::{Base, B128, B16, B256, B32, B64};
use halo2_proofs::halo2curves::{bn256::Fr, pasta::Fp};

/// Extend Fr and Fp field
#[macro_export]
macro_rules! extend_field {
    ($primitive:ident) => {
        impl From<$primitive> for Fr {
            fn from(value: $primitive) -> Self {
                Fr::from_bytes(&value.fixed_le_bytes())
                    .expect("Unable to deserialize Fr from bytes")
            }
        }

        impl From<$primitive> for Fp {
            fn from(value: $primitive) -> Self {
                let value = value.fixed_le_bytes();
                // Convert [u8; 32] to [u64; 4]
                let mut chunk: [u64; 4] = [0u64; 4];
                for i in 0..4 {
                    let limb = &value[i * 8..(i + 1) * 8];
                    chunk[i] = u64::from_le_bytes(
                        limb.try_into()
                            .expect("Unable to deserialize Fp from bytes"),
                    );
                }
                Fp::from_raw(chunk)
            }
        }
    };
}

extend_field!(B256);
extend_field!(B128);
extend_field!(B64);
extend_field!(B32);
extend_field!(B16);
