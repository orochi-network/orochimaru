use bytes::{BufMut, BytesMut};
use libecvrf::{
    extends::ScalarExtend,
    secp256k1::{
        curve::{Affine, Scalar},
        sign_with_context, Message, SecretKey, ECMULT_GEN_CONTEXT,
    },
    ECVRFContractProof,
};
use std::{io::Write, str};
use tiny_keccak::{Hasher, Keccak};

use crate::rpc::decode_address;

const ETHEREUM_MESSAGE_PREFIX: &str = "\x19Ethereum Signed Message:\n";

/// Sign an Ethereum message with prefix
pub fn sign_ethereum_message(sk: &SecretKey, message: &Vec<u8>) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(256);
    let prefix = format!("{}{}", ETHEREUM_MESSAGE_PREFIX, message.len()).into_bytes();
    buf.put(prefix.as_slice());
    buf.put(message.as_slice());
    let prefixed_message = Message(Scalar::keccak256(&buf));
    let (signature, recovery_id) = sign_with_context(&prefixed_message, sk, &ECMULT_GEN_CONTEXT);
    let mut recover_id: u8 = recovery_id.into();
    // Recover id must be 27 or 28, if it was 0,1 we will add 27
    if recover_id < 27 {
        recover_id += 27;
    }
    let mut r = Vec::new();
    r.write_all(&signature.serialize()).unwrap();
    r.write_all(&[recover_id]).unwrap();
    r.write_all(message).unwrap();
    r
}

pub fn ecvrf_proof_checksum(
    receiver_address: String,
    smart_contract_proof: &ECVRFContractProof,
) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut buf = BytesMut::new();
    let mut output = [0u8; 32];

    // Receiver address
    buf.put_slice(
        hex::decode(decode_address(receiver_address).replace("0x", ""))
            .expect("Unable to decode receiver address")
            .as_slice(),
    );

    // Gamma
    buf.put_slice(&smart_contract_proof.gamma.x.b32());
    buf.put_slice(&smart_contract_proof.gamma.y.b32());
    // C
    buf.put_slice(&smart_contract_proof.c.b32());
    // S
    buf.put_slice(&smart_contract_proof.s.b32());
    // Alpha
    buf.put_slice(&smart_contract_proof.alpha.b32());
    // Witness address
    // Padding 96 bits on ther left then 160 bits of witness address
    // Witness address was calculated before, so it store in 0 -> 20
    // not 12 -> 32
    // buf.put_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    buf.put_slice(&smart_contract_proof.witness_address.b32()[0..20]);
    // Gama Witness
    buf.put_slice(&smart_contract_proof.witness_gamma.x.b32());
    buf.put_slice(&smart_contract_proof.witness_gamma.y.b32());
    // Hash Witness
    buf.put_slice(&smart_contract_proof.witness_hash.x.b32());
    buf.put_slice(&smart_contract_proof.witness_hash.y.b32());
    // Inverted Z
    buf.put_slice(&smart_contract_proof.inverse_z.b32());

    hasher.update(&buf.freeze());
    hasher.finalize(&mut output);

    output
}

pub fn ecvrf_proof_digest(smart_contract_proof: &ECVRFContractProof) -> [u8; 32] {
    let mut affine_pub_key: Affine = smart_contract_proof.pk.into();
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let mut buf = BytesMut::new();
    affine_pub_key.x.normalize();
    affine_pub_key.y.normalize();

    // Public key
    buf.put_slice(&affine_pub_key.x.b32());
    buf.put_slice(&affine_pub_key.y.b32());
    // Gamma
    buf.put_slice(&smart_contract_proof.gamma.x.b32());
    buf.put_slice(&smart_contract_proof.gamma.y.b32());
    // C
    buf.put_slice(&smart_contract_proof.c.b32());
    // S
    buf.put_slice(&smart_contract_proof.s.b32());
    // Alpha
    buf.put_slice(&smart_contract_proof.alpha.b32());
    // Witness address
    // Padding 96 bits on ther left then 160 bits of witness address
    // Witness address was calculated before, so it store in 0 -> 20
    // not 12 -> 32
    // buf.put_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    buf.put_slice(&smart_contract_proof.witness_address.b32()[0..20]);
    // Gama Witness
    buf.put_slice(&smart_contract_proof.witness_gamma.x.b32());
    buf.put_slice(&smart_contract_proof.witness_gamma.y.b32());
    // Hash Witness
    buf.put_slice(&smart_contract_proof.witness_hash.x.b32());
    buf.put_slice(&smart_contract_proof.witness_hash.y.b32());
    // Inverted Z
    buf.put_slice(&smart_contract_proof.inverse_z.b32());

    hasher.update(&buf.freeze());
    hasher.finalize(&mut output);

    output
}

/// Compose operator proof
pub fn compose_operator_proof(
    nonce: i64,
    receiver: &[u8; 20],
    ecvrf_proof_digest: &[u8; 32],
) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(256);
    // We don't have uint96 in Rust
    // So we combine u32 with i64
    buf.put_u32(0);
    buf.put_i64(nonce);
    buf.put(receiver.as_slice());
    buf.put(ecvrf_proof_digest.as_slice());
    buf.to_vec()
}
