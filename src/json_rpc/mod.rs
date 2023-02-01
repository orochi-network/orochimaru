use core::panic;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JSONRPCPayload {
    method: String,
    params: Vec<String>,
}

pub enum JSONRPCMethod {
    // New epoch of given network
    OrandNewEpoch(u64, String),
    // Network, receiverAddress, epoch
    OrandGetEpoch(u64, String, u64),
    // New epoch of given network
    OrandNewPrivateEpoch(u64, String),
    // Get public key
    OrandGetPublicKey(String),
}

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

fn decode_u64(val: String) -> u64 {
    let regex_u64 = Regex::new(r#"\d{1,10}"#).expect("Unable to init Regex");
    match regex_u64.is_match(val.as_str().as_ref()) {
        true => val
            .as_str()
            .parse::<u64>()
            .expect("Unable to parse &str to u64"),
        false => panic!("Invalid input u64 value"),
    }
}

fn decode_address(val: String) -> String {
    let regex_address = Regex::new(r#"^0x[a-fA-F0-9]{40}$"#).expect("Unable to init Regex");
    match regex_address.is_match(val.as_str().as_ref()) {
        true => val.clone(),
        false => panic!("Invalid input address value"),
    }
}

fn decode_name(val: String) -> String {
    let regex_name = Regex::new(r#"^[a-zA-Z0-9\s]{3,40}$"#).expect("Unable to init Regex");
    match regex_name.is_match(val.as_str().as_ref()) {
        true => val.clone(),
        false => panic!("Invalid input name value"),
    }
}

impl JSONRPCMethod {
    pub fn from_json_string(json_string: &str) -> Self {
        let json_rpc: JSONRPCPayload = serde_json::from_str(json_string).unwrap();
        match json_rpc.method.as_str() {
            "orand_getPublicEpoch" => Self::OrandGetEpoch(
                decode_u64(json_rpc.params[0].clone()),
                ZERO_ADDRESS.to_string(),
                decode_u64(json_rpc.params[1].clone()),
            ),
            "orand_getPrivateEpoch" => Self::OrandGetEpoch(
                decode_u64(json_rpc.params[0].clone()),
                decode_address(json_rpc.params[1].clone()),
                decode_u64(json_rpc.params[2].clone()),
            ),
            "orand_newPublicEpoch" => Self::OrandNewEpoch(
                decode_u64(json_rpc.params[0].clone()),
                ZERO_ADDRESS.to_string(),
            ),
            "orand_newPrivateEpoch" => Self::OrandNewEpoch(
                decode_u64(json_rpc.params[0].clone()),
                decode_address(json_rpc.params[1].clone()),
            ),
            "orand_getPublicKey" => {
                Self::OrandGetPublicKey(decode_name(json_rpc.params[0].clone()))
            }
            _ => panic!("Unsupported method"),
        }
    }
}
