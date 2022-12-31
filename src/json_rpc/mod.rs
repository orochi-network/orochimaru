use core::panic;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JSONRPCPayload {
    method: String,
    params: Vec<String>,
}

pub enum JSONRPCMethod {
    // New epoch of given network
    OrandNewEpoch(u32, String),
    // Network, receiverAddress, epoch
    OrandGetEpoch(u32, String, u32),
    // New epoch of given network
    OrandNewPrivateEpoch(u32, String),
    // Get public key
    OrandGetPublicKey(String),
}

impl JSONRPCMethod {
    pub fn from_json_string(json_string: &str) -> Self {
        let json_rpc: JSONRPCPayload = serde_json::from_str(json_string).unwrap();
        match json_rpc.method.as_str() {
            "orand_getPublicEpoch" => Self::OrandGetEpoch(
                json_rpc.params[0].as_str().parse().unwrap(),
                "0x0000000000000000000000000000000000000000".to_string(),
                json_rpc.params[1].as_str().parse().unwrap(),
            ),
            "orand_getPrivateEpoch" => Self::OrandGetEpoch(
                json_rpc.params[0].as_str().parse().unwrap(),
                json_rpc.params[1].to_string(),
                json_rpc.params[2].as_str().parse().unwrap(),
            ),
            "orand_newPublicEpoch" => Self::OrandNewEpoch(
                json_rpc.params[0].as_str().parse().unwrap(),
                "0x0000000000000000000000000000000000000000".to_string(),
            ),
            "orand_newPrivateEpoch" => Self::OrandNewEpoch(
                json_rpc.params[0].as_str().parse().unwrap(),
                json_rpc.params[1].to_string(),
            ),
            "orand_getPublicKey" => Self::OrandGetPublicKey(json_rpc.params[0].to_string()),
            _ => panic!("Unsupported method"),
        }
    }
}
