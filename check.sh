#!/usr/bin/env bash

cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all -- -D warnings