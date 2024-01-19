use crate::Error;
use base64_url;
use hex;
use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// JWT Payload
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct JWTPayload {
    /// User name
    pub user: String,
    /// Nonce
    pub nonce: u32,
    /// Unix timestamp
    pub timestamp: u64,
}

/// JWT
pub struct JWT {
    secret_key: Vec<u8>,
}

impl JWT {
    /// Create new instance of JWT
    pub fn new(secret_hex_string: &str) -> Self {
        JWT {
            secret_key: hex::decode(secret_hex_string.replace("0x", "").replace("0X", ""))
                .expect("Unable to decode secret key"),
        }
    }

    /// Encode payload to JWT
    pub fn decode_payload(json_web_token: &str) -> Result<JWTPayload, Error> {
        let split_jwt: Vec<&str> = json_web_token.trim().split('.').collect();
        if split_jwt.len() == 3 {
            let decoded_payload = match base64_url::decode(&split_jwt[1]) {
                Ok(payload) => payload,
                Err(_) => return Err(Error("INVALID_PAYLOAD", "Unable to decode payload")),
            };
            let regex_name = Regex::new(r#"^[a-zA-Z0-9]{3,40}$"#).expect("Unable to init Regex");
            let jwt_payload: JWTPayload = match serde_json::from_slice(&decoded_payload) {
                Ok(payload) => payload,
                Err(_) => return Err(Error("INVALID_PAYLOAD", "Unable to deserialize payload")),
            };
            if regex_name.is_match(&jwt_payload.user) {
                return Ok(jwt_payload);
            } else {
                return Err(Error("INVALID_USERNAME", "Invalid username"));
            }
        }
        Err(Error("INVALID_JWT", "Invalid JWT format"))
    }

    /// Encode payload to JWT
    pub fn verify(&self, json_web_token: &str) -> bool {
        let split_jwt: Vec<&str> = json_web_token.trim().split('.').collect();
        if split_jwt.len() == 3 {
            let payload = split_jwt[1];
            let signature = split_jwt[2];
            let mut mac = HmacSha256::new_from_slice(&self.secret_key)
                .expect("HMAC can take key of any size");
            mac.update(&base64_url::decode(&payload).expect("Unable to decode base64 payload"));
            return mac
                .verify_slice(
                    &base64_url::decode(&signature).expect("Unable to decode base64 signature"),
                )
                .is_ok();
        }
        false
    }
}
