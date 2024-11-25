//! This crate provide ECVRF implementation in Rust.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    unused,
    warnings,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs,
    unused_imports
)]
#![forbid(unsafe_code)]

/// EC-VRF implementation in Rust
mod ecvrf;
pub use ecvrf::*;

/// EC-VRF error handling
pub mod error;

/// Extended Affine, Jacobian, Scalar, Field
pub mod extend;

/// Curve hash
pub mod hash;

/// Helper functions
pub mod helper;

/// Re-export libsecp256k1
pub use tiny_ec::*;

/// Re-export rand::thread_rng
pub mod util {
    pub use rand::thread_rng;
}
