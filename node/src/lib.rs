//! All necessary modules for the node
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

/// Handle ethereum signing
pub mod ethereum;

mod sqlite;
pub use sqlite::*;

/// JSON Web Token
pub mod jwt;

/// JSON RPC
pub mod rpc;

/// Error handling
mod error;
pub use error::Error;

mod quick_response;
pub use quick_response::*;

mod node_context;
pub use node_context::*;
