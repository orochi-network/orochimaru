#[deny(warnings, unused, nonstandard_style, missing_docs, unsafe_code)]
use bytes::Bytes;
use dotenv::dotenv;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::Body,
    server::conn::http1,
    service::service_fn,
    {Method, Request, Response, StatusCode},
};
use hyper_util::rt::TokioIo;
use libecvrf::{
    extends::{AffineExtend, ScalarExtend},
    helper::{get_address, random_bytes},
    secp256k1::{curve::Scalar, PublicKey, SecretKey},
    KeyPair, RawKeyPair, ECVRF,
};

use node::{
    ethereum::{compose_operator_proof, sign_ethereum_message},
    json_rpc::{JSONRPCMethod, ZERO_ADDRESS},
    jwt::JWT,
    sqlite_db::SQLiteDB,
};

use serde_json::json;
use std::{borrow::Borrow, env, net::SocketAddr, str::from_utf8, sync::Arc};
use tokio::net::TcpListener;
use uuid::Uuid;

const ORAND_KEYRING_NAME: &str = "orand";

struct QuickResponse<T> {
    status: StatusCode,
    body: T,
}

impl<T: Into<Bytes> + Clone> QuickResponse<T> {
    pub fn new(status: StatusCode, body: T) -> Self {
        QuickResponse { status, body }
    }

    pub fn body(&mut self, body: T) -> &Self {
        self.body = body;
        self
    }

    pub fn invoke(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let builder = Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Content-Type", "application/json");

        let mut resp = builder
            .body(full(self.body.clone()))
            .expect("Unable to construct body");

        *resp.status_mut() = self.status;

        resp
    }

    pub fn ok(&self) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        Ok(self.invoke())
    }
}

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn orand(
    req: Request<hyper::body::Incoming>,
    sqlite: Arc<SQLiteDB>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let (header, body) = req.into_parts();
    let randomness = sqlite.table_randomness();
    let mut quick_response = QuickResponse::new(StatusCode::OK, "".to_string());
    let keyring = sqlite.table_keyring();
    // Check if it's testnet or not
    let is_testnet = match env::var("ORAND_TESTNET") {
        Ok(s) => s.trim().to_lowercase().eq("true"),
        _ => false,
    };

    match (&header.method, header.uri.path()) {
        // Handle all post method to JSON RPC
        (&Method::POST, "/") => {
            let max = body.size_hint().upper().unwrap_or(u64::MAX);

            // Body is 64 KB
            if max > 1024 * 64 {
                return QuickResponse::new(
                    hyper::StatusCode::PAYLOAD_TOO_LARGE,
                    "{\"success\":false, \"message\":\"Your body too big, can not fit the body bag\"}"
                ).ok();
            }
            // Body to byte
            let whole_body = body
                .collect()
                .await
                .expect("Unable to collect the request body")
                .to_bytes();
            let json_string =
                from_utf8(whole_body.borrow()).expect("Unable to convert body to utf8");
            let json_rpc_payload = JSONRPCMethod::from_json_string(json_string);

            match json_rpc_payload {
                // Get epoch, it's alias of orand_getPublicEpoch() and orand_getPrivateEpoch()
                JSONRPCMethod::OrandGetEpoch(network, address, epoch) => {
                    let recent_epochs = randomness
                        .find_recent_epoch(network, &address, epoch)
                        .await
                        .expect("Can not get recent epoch");

                    return QuickResponse::new(
                        hyper::StatusCode::OK,
                        serde_json::to_string_pretty(&recent_epochs)
                            .expect("Can not serialize data"),
                    )
                    .ok();
                }
                // Get epoch, it's alias of orand_newPublicEpoch() and orand_newPrivateEpoch()
                JSONRPCMethod::OrandNewEpoch(network, address) => {
                    let receiver = sqlite.table_receiver();

                    // Decode JWT payload, this code is dirty let try catch_unwind next time
                    let (jwt_payload, json_web_token) = match header.headers.get("authorization") {
                        Some(e) => match e.to_str() {
                            Ok(s) => match JWT::decode_payload(&s.to_string()) {
                                Some(p) => (p, s),
                                None => {
                                    return QuickResponse::new(
                                            StatusCode::FORBIDDEN,
                                            "{\"success\":false, \"message\":\"Unable to decode authorization header\"}")
                                            .ok();
                                }
                            },
                            Err(_) => {
                                return QuickResponse::new(
                                        StatusCode::FORBIDDEN,
                                        "{\"success\":false, \"message\":\"Unable to decode authorization header\"}")
                                        .ok();
                            }
                        },
                        None => {
                            return QuickResponse::new(
                                StatusCode::FORBIDDEN,
                                "{\"success\":false, \"message\":\"Access denied, this method required authorization\"}")
                                .ok();
                        }
                    };

                    // Reconstruct secret key from database
                    let user_record = match keyring
                        .find_by_name(jwt_payload.user.clone())
                        .await
                        .expect("Can not query our database")
                    {
                        Some(record) => record,
                        None => {
                            return QuickResponse::new(
                                StatusCode::FORBIDDEN,
                                "{\"success\":false, \"message\":\"Access denied, this method required authorization\"}")
                                .ok();
                        }
                    };

                    // Reconstruct secret key from database
                    let keyring_record = match keyring
                        .find_by_name(ORAND_KEYRING_NAME.to_string())
                        .await
                        .expect("Can not query our database")
                    {
                        Some(record) => record,
                        None => {
                            return QuickResponse::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "{\"success\":false, \"message\":\"Orand key was not init\"}",
                            )
                            .ok();
                        }
                    };

                    // Only orand could able to create public epoch
                    if address.eq(ZERO_ADDRESS) && !jwt_payload.user.eq(ORAND_KEYRING_NAME) {
                        return QuickResponse::new(
                            StatusCode::FORBIDDEN,
                            "{\"success\":false, \"message\":\"Access denied, you do not have ability to create public\"}")
                            .ok();
                    }

                    let jwt = JWT::new(&user_record.hmac_secret);
                    if !jwt.verify(&json_web_token.to_string()) {
                        return QuickResponse::new(
                            StatusCode::FORBIDDEN,
                            "{\"success\":false, \"message\":\"Access denied, incorrect key\"}",
                        )
                        .ok();
                    }

                    // Reconstruct secret key from database
                    let receiver_record = match receiver
                        .find_one(network, &address)
                        .await
                        .expect("Can not query our database")
                    {
                        Some(record) => record,
                        None => {
                            if is_testnet {
                                // Add new record of receiver if we're on testnet
                                receiver
                                    .insert(json!({
                                        "name": format!("{}-{}", jwt_payload.user.clone(), Uuid::new_v4()),
                                        "network": network,
                                        "address": address.clone(),
                                        "nonce": 0
                                    }))
                                    .await
                                    .expect("Unable to inzer new receiver")
                            } else {
                                return QuickResponse::new(
                                    StatusCode::NOT_FOUND,
                                    "{\"success\":false, \"message\":\"Receiver was not registered\"}")
                                    .ok();
                            }
                        }
                    };

                    let returning_receiver = receiver
                        .update(&receiver_record, network, &address)
                        .await
                        .expect("Unable to update receiver")
                        .expect("Data was insert but not found, why?");

                    let secret_key = SecretKey::parse(
                        hex::decode(keyring_record.secret_key)
                            .expect("Unable to decode secret key")
                            .as_slice()
                            .try_into()
                            .expect("Can not convert secret key to [u8; 32]"),
                    )
                    .expect("Can not reconstruct secret key");

                    let vrf = ECVRF::new(secret_key);

                    let latest_epoch_record = randomness
                        .find_latest_epoch(network, &address)
                        .await
                        .expect("Can not get latest epoch");

                    let (current_alpha, next_epoch) = match latest_epoch_record {
                        Some(latest_epoch) => (
                            Scalar::from_bytes(
                                hex::decode(latest_epoch.y)
                                    .expect("Unable to decode previous result")
                                    .as_slice()
                                    .try_into()
                                    .expect("Unable to convert to [u8; 32]"),
                            ),
                            latest_epoch.epoch + 1,
                        ),
                        None => {
                            // Get alpha from random entropy
                            (Scalar::randomize(), 0)
                        }
                    };

                    let contract_proof = vrf.prove_contract(&current_alpha);

                    let bytes_address: [u8; 20] =
                        hex::decode(address.replace("0x", "").replace("0X", ""))
                            .expect("Unable to decode address")
                            .as_slice()
                            .try_into()
                            .expect("Unable to convert to [u8; 20] address");
                    let raw_proof = compose_operator_proof(
                        receiver_record.nonce as u64,
                        &bytes_address,
                        &contract_proof.y,
                    );
                    let ecdsa_proof = sign_ethereum_message(&secret_key, &raw_proof);

                    let returning_randomness = randomness
                        .insert(json!({
                            "keyring_id": keyring_record.id,
                            "receiver_id": returning_receiver.id,
                            "epoch": next_epoch,
                            "alpha":hex::encode(current_alpha.b32()),
                            "gamma": contract_proof.gamma.to_hex_string(),
                            "c":hex::encode(&contract_proof.c.b32()),
                            "s":hex::encode(&contract_proof.s.b32()),
                            "y":hex::encode(&contract_proof.y.b32()),
                            "witness_address": hex::encode(contract_proof.witness_address.b32())[24..64],
                            "witness_gamma": contract_proof.witness_gamma.to_hex_string(),
                            "witness_hash": contract_proof.witness_hash.to_hex_string(),
                            "inverse_z": hex::encode(contract_proof.inverse_z.b32()),
                            "signature_proof": hex::encode(&ecdsa_proof),
                        }))
                        .await
                        .expect("Unable to insert new epoch");

                    quick_response
                        .body(
                            serde_json::to_string_pretty(&returning_randomness)
                                .expect("Unable to serialized result"),
                        )
                        .ok()
                }
                JSONRPCMethod::OrandGetPublicKey(key_name) => {
                    let key_record = keyring
                        .find_by_name(key_name)
                        .await
                        .expect("Can find the given key name");

                    quick_response
                        .body(
                            serde_json::to_string_pretty(&key_record)
                                .expect("Can not serialize data"),
                        )
                        .ok()
                }
                _ => QuickResponse::new(
                    StatusCode::NOT_IMPLEMENTED,
                    "{\"success\": \"false\", \"message\": \"It is not working in this way\"}",
                )
                .ok(),
            }
        }
        _ => QuickResponse::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "{\"success\": \"false\", \"message\": \"It is not working in this way\"}",
        )
        .ok(),
    }
}

/*
fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}*/

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenv().ok();
    let addr = SocketAddr::from(([0, 0, 0, 0], 1337));
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    // TODO Move these to another module, we should separate between KEYS and API
    let sqlite = Arc::new(SQLiteDB::new(database_url).await);
    let keyring = sqlite.table_keyring();
    let result_keyring = keyring
        .find_by_name(ORAND_KEYRING_NAME.to_string())
        .await
        .expect("Unable to query keyring table");

    // Create new key if not exist
    let keyring_record = match result_keyring {
        None => {
            // Generate key if it didn't exist
            let mut hmac_secret = [0u8; 16];
            random_bytes(&mut hmac_secret);
            let new_keypair = match env::var("SECRET_KEY") {
                // Get secret from .env file
                Ok(r) => {
                    let k: [u8; 32] = hex::decode(r.trim())
                        .expect("Unable to decode secret key")
                        .try_into()
                        .expect("Unable to convert secret key to [u8; 32]");
                    RawKeyPair::from(&k)
                }
                // Generate new secret
                Err(_) => RawKeyPair::from(KeyPair::new()),
            };
            keyring
                .insert(json!({
                "username": ORAND_KEYRING_NAME,
                "hmac_secret": hex::encode(hmac_secret),
                "public_key": hex::encode(new_keypair.public_key), 
                "secret_key": hex::encode(new_keypair.secret_key)}))
                .await
                .expect("Unable to insert new key to keyring table")
        }
        Some(k) => k,
    };
    let pk = PublicKey::parse(
        hex::decode(keyring_record.public_key)
            .expect("Unable to decode public key")
            .as_slice()
            .try_into()
            .expect("Unable to convert public key to [u8; 65]"),
    )
    .expect("Wrong public key format");
    println!("Public Key: {}", hex::encode(pk.serialize()));
    println!("Address of public key: 0x{}", hex::encode(get_address(pk)));

    let listener = TcpListener::bind(addr).await?;

    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let sqlite_instance = sqlite.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| orand(req, sqlite_instance.clone())),
                )
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
