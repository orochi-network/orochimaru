use base64_url;
use hex;
use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JWTPayload {
    pub user: String,
    pub nonce: u32,
    pub timestamp: u64,
}

pub struct JWT {
    secret_key: Vec<u8>,
}

impl JWT {
    pub fn new(secret_hex_string: &String) -> Self {
        JWT {
            secret_key: hex::decode(secret_hex_string.replace("0x", "").replace("0X", ""))
                .expect("Unable to decode secret key"),
        }
    }

    pub fn decode_payload(json_web_token: &String) -> Option<JWTPayload> {
        let split_jwt: Vec<&str> = json_web_token.trim().split(".").collect();
        if split_jwt.len() == 3 {
            let decoded_payload =
                base64_url::decode(&split_jwt[1]).expect("Unable to decode payload");
            let regex_name = Regex::new(r#"^[a-zA-Z0-9\s]{3,40}$"#).expect("Unable to init Regex");
            let jwt_payload: JWTPayload =
                serde_json::from_slice(&decoded_payload).expect("Unable to deserialize payload");
            if regex_name.is_match(&jwt_payload.user) {
                return Some(jwt_payload);
            } else {
                return None;
            }
        }
        None
    }

    pub fn verify(&self, json_web_token: &String) -> bool {
        let split_jwt: Vec<&str> = json_web_token.trim().split(".").collect();
        if split_jwt.len() == 3 {
            let payload = split_jwt[1];
            let signature = split_jwt[2];
            let mut mac = HmacSha256::new_from_slice(&self.secret_key)
                .expect("HMAC can take key of any size");
            mac.update(&base64_url::decode(&payload).expect("Unable to decode base64 payload"));
            return match mac.verify_slice(
                &base64_url::decode(&signature).expect("Unable to decode base64 signature"),
            ) {
                Ok(_) => true,
                _ => false,
            };
        }
        false
    }
}
