use ecvrf::{helper::randomize, random::thread_rng, secp256k1::SecretKey, ECVRF};
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let (shutdown_send, mut shutdown_recv) = mpsc::unbounded_channel::<i32>();

    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = shutdown_recv.recv() => {},
    }
}
