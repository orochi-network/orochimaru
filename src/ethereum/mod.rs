use bytes::{BufMut, BytesMut};
use ecvrf::{
    helper::keccak256_vec_scalar,
    secp256k1::{curve::Scalar, sign_with_context, Message, SecretKey, ECMULT_GEN_CONTEXT},
};
use std::{io::Write, str};

const ETHEREUM_MESSAGE_PREFIX: &str = "\x19Ethereum Signed Message:\n";

//Sign an Ethereum message with prefix
pub fn sign_ethereum_message(sk: &SecretKey, message: &Vec<u8>) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(128);
    let prefix = format!("{}{}", ETHEREUM_MESSAGE_PREFIX, message.len().to_string()).into_bytes();
    buf.put(prefix.as_slice());
    buf.put(message.as_slice());
    let message = Message(keccak256_vec_scalar(&buf.to_vec()));
    let (signature, recovery_id) = sign_with_context(&message, &sk, &ECMULT_GEN_CONTEXT);
    let mut r = Vec::new();
    r.write(&signature.serialize()).unwrap();
    r.write(&[recovery_id.into()]).unwrap();
    r.write(&buf.to_vec()).unwrap();
    r
}

// Compose operator proof
pub fn compose_operator_proof(nonce: u64, receiver: &[u8; 20], y: Scalar) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(128);
    buf.put_u32(0);
    buf.put_u64(nonce);
    buf.put(receiver.as_slice());
    buf.put(y.b32().as_slice());
    buf.to_vec()
}
