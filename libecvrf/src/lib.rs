/// EC-VRF implementation in Rust
#[deny(warnings, unused, nonstandard_style, missing_docs, unsafe_code)]
mod ecvrf;

pub use ecvrf::{error, extends, hash, helper};

pub use ecvrf::ecvrf::*;

pub mod secp256k1 {
    pub use libsecp256k1::*;
}

pub mod util {
    pub use rand::thread_rng;
}
