#!/usr/bin/env bash

cargo build
RUST_BACKTRACE=full cargo test
cargo fmt --all -- --check
cargo clippy --all -- -D warnings