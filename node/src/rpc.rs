use crate::error::Error;
use core::panic;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// JSON RPC Payload
pub struct JSONRPCPayload {
    method: String,
    params: Vec<String>,
}

/// JSON RPC Method
pub enum JSONRPCMethod {
    /// New epoch (network id, receiver address)
    OrandNewEpoch(u32, String),
    /// Get epoch (network id, receiver address, epoch id)
    OrandGetEpoch(u32, String, u32),
    /// New epoch of given network (network id, receiver address)
    OrandNewPrivateEpoch(u32, String),
    /// Get public key (name)
    OrandGetPublicKey(String),
}

/// Zero address
pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

fn decode_u32(val: String) -> u32 {
    let regex_u32 = Regex::new(r#"\d{1,10}"#).expect("Unable to init Regex");
    match regex_u32.is_match(val.as_str().as_ref()) {
        true => val.as_str().parse::<u32>().expect("Unable to parse u32"),
        false => panic!("Invalid input u32 value"),
    }
}

fn decode_address(val: String) -> String {
    let regex_address = Regex::new(r#"^0x[a-fA-F0-9]{40}$"#).expect("Unable to init Regex");
    match regex_address.is_match(val.as_str().as_ref()) {
        true => val.clone().to_lowercase(),
        false => panic!("Invalid input address value"),
    }
}

fn decode_name(val: String) -> String {
    let regex_name = Regex::new(r#"^[a-zA-Z0-9]{3,40}$"#).expect("Unable to init Regex");
    match regex_name.is_match(val.as_str().as_ref()) {
        true => val.clone(),
        false => panic!("Invalid input name value"),
    }
}

impl JSONRPCMethod {
    /// Create new instance of JSONRPCMethod from JSON string
    pub fn from_json_string(json_string: &str) -> Result<Self, Error> {
        let json_rpc: JSONRPCPayload = match serde_json::from_str(json_string) {
            Ok(json_rpc) => json_rpc,
            Err(_) => return Err(Error("INVALID_JSON", "Invalid JSON")),
        };
        let result = match json_rpc.method.as_str() {
            "orand_getPublicEpoch" => Self::OrandGetEpoch(
                decode_u32(json_rpc.params[0].clone()),
                ZERO_ADDRESS.to_string(),
                decode_u32(json_rpc.params[1].clone()),
            ),
            "orand_getPrivateEpoch" => Self::OrandGetEpoch(
                decode_u32(json_rpc.params[0].clone()),
                decode_address(json_rpc.params[1].clone()),
                decode_u32(json_rpc.params[2].clone()),
            ),
            "orand_newPublicEpoch" => Self::OrandNewEpoch(
                decode_u32(json_rpc.params[0].clone()),
                ZERO_ADDRESS.to_string(),
            ),
            "orand_newPrivateEpoch" => Self::OrandNewEpoch(
                decode_u32(json_rpc.params[0].clone()),
                decode_address(json_rpc.params[1].clone()),
            ),
            "orand_getPublicKey" => {
                Self::OrandGetPublicKey(decode_name(json_rpc.params[0].clone()))
            }
            _ => return Err(Error("INVALID_METHOD", "Unsupported method")),
        };
        Ok(result)
    }
}
