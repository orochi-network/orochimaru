//! All necessary modules for the node
#![deny(
    unused,
    warnings,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs,
    unused_imports
)]
#![forbid(unsafe_code)]

use bytes::Bytes;
use dotenv::dotenv;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{
    body::Body,
    server::conn::http1,
    service::service_fn,
    {Method, Request, Response},
};
use hyper_util::rt::TokioIo;
use libecvrf::{
    extends::{AffineExtend, ScalarExtend},
    helper::{get_address, random_bytes},
    secp256k1::curve::Scalar,
    KeyPair, RawKeyPair, Zeroable,
};

use node::{
    ethereum::{compose_operator_proof, sign_ethereum_message},
    jwt::{JWTPayload, JWT},
    randomness::ActiveModel as RadomnessActiveModel,
    receiver::ActiveModel as ReceiverActiveModel,
    rpc::{JSONRPCMethod, ZERO_ADDRESS},
    NodeContext, QuickResponse, SQLiteDB,
};

use sea_orm::ActiveValue;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{borrow::Borrow, env, net::SocketAddr, str::from_utf8, sync::Arc};
use tokio::net::TcpListener;
use uuid::Uuid;

const ORAND_KEYRING_NAME: &str = "orand";
const ORAND_HMAC_KEY_SIZE: usize = 32;

/// Return a JSON record of user
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserResponse {
    /// Username
    pub username: String,
    /// Hmac secret
    pub hmac_secret: String,
    /// Public key
    pub public_key: String,
    /// Created date
    pub created_date: String,
}

async fn orand_get_epoch(
    network: u32,
    address: String,
    epoch: u32,
    context: Arc<NodeContext>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let sqlite = context.sqlite();
    let randomness = sqlite.table_randomness();
    match randomness.find_recent_epoch(network, &address, epoch).await {
        Ok(recent_epochs) => QuickResponse::res_json(&recent_epochs),
        Err(_) => QuickResponse::err(node::Error("NOT_FOUND", "Epoch was not found")),
    }
}

async fn orand_new_epoch(
    jwt_payload: JWTPayload,
    network: u32,
    address: String,
    epoch_id: u32,
    context: Arc<NodeContext>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let sqlite = context.sqlite();
    let receiver = sqlite.table_receiver();
    let randomness = sqlite.table_randomness();
    let ecvrf = context.ecvrf();

    // Reconstruct secret key from database
    let receiver_record = match receiver
        .find_one(network, &address)
        .await
        .expect("Can not query our database")
    {
        Some(record) => record,
        None => {
            if context.is_testnet() {
                // Add new record of receiver if we're on testnet
                match receiver
                    .insert(json!({
                        "name": format!("{}-{}", jwt_payload.user.clone(), Uuid::new_v4()),
                        "network": network,
                        "address": address.clone(),
                        "nonce": 0
                    }))
                    .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        return QuickResponse::err(node::Error(
                            "DATABASE_ERROR",
                            "Unable to insert new receiver",
                        ));
                    }
                }
            } else {
                return QuickResponse::err(node::Error(
                    "RECEIVER_NOT_FOUND",
                    "Receiver was not found",
                ));
            }
        }
    };

    let returning_randomness = match randomness
        .find_given_epoch(network, &address, epoch_id)
        .await
        .expect("Unable to query randomness table")
    {
        Some(randomness_record) => {
            // Retry given epoch
            let mut buf = [0u8; 32];
            hex::decode_to_slice(randomness_record.alpha.clone(), &mut buf)
                .expect("Unable to decode previous result");

            let contract_proof = match ecvrf.prove_contract(&Scalar::from_bytes(&buf)) {
                Ok(r) => r,
                Err(_) => {
                    return QuickResponse::err(node::Error(
                        "ECVRF_ERROR",
                        "Unable to generate proof",
                    ));
                }
            };

            let mut bytes_address = [0u8; 20];
            hex::decode_to_slice(
                address.replace("0x", "").replace("0X", ""),
                &mut bytes_address,
            )
            .expect("Unable to decode address");

            let raw_proof = compose_operator_proof(
                randomness_record.epoch as u64,
                &bytes_address,
                &contract_proof.y,
            );
            let ecdsa_proof = sign_ethereum_message(&context.keypair().secret_key, &raw_proof);

            let mut active_model = RadomnessActiveModel::from(randomness_record);
            active_model.gamma = ActiveValue::Set(contract_proof.gamma.to_hex_string());
            active_model.c = ActiveValue::Set(hex::encode(contract_proof.c.b32()));
            active_model.s = ActiveValue::Set(hex::encode(contract_proof.s.b32()));
            active_model.y = ActiveValue::Set(hex::encode(contract_proof.y.b32()));
            active_model.witness_address = ActiveValue::Set(
                hex::encode(contract_proof.witness_address.b32())[0..40].to_string(),
            );
            active_model.witness_gamma =
                ActiveValue::Set(contract_proof.witness_gamma.to_hex_string());
            active_model.witness_hash =
                ActiveValue::Set(contract_proof.witness_hash.to_hex_string());
            active_model.inverse_z = ActiveValue::Set(hex::encode(contract_proof.inverse_z.b32()));
            active_model.signature_proof = ActiveValue::Set(hex::encode(&ecdsa_proof));

            randomness
                .update(active_model)
                .await
                .expect("Unable to update epoch")
        }
        None => {
            // Update nonce of the receiver
            let receiver_nonce = receiver_record.nonce;
            let mut receiver_active_model = ReceiverActiveModel::from(receiver_record);
            receiver_active_model.nonce = ActiveValue::Set(receiver_nonce + 1);
            let receiver_record = receiver
                .update(receiver_active_model)
                .await
                .expect("Unable to update nonce");

            let (current_alpha, next_epoch) = match randomness
                .find_latest_epoch(network, &address)
                .await
                .expect("Can not get latest epoch")
            {
                Some(latest_epoch) => {
                    let mut buf = [0u8; 32];
                    hex::decode_to_slice(latest_epoch.y, &mut buf)
                        .expect("Unable to decode previous result");
                    (Scalar::from_bytes(&buf), latest_epoch.epoch + 1)
                }
                None => {
                    // Get alpha from random entropy
                    (Scalar::randomize(), 0)
                }
            };
            let contract_proof = match ecvrf.prove_contract(&current_alpha) {
                Ok(r) => r,
                Err(_) => {
                    return QuickResponse::err(node::Error(
                        "ECVRF_ERROR",
                        "Unable to generate proof",
                    ));
                }
            };

            let mut bytes_address = [0u8; 20];
            hex::decode_to_slice(
                address.replace("0x", "").replace("0X", ""),
                &mut bytes_address,
            )
            .expect("Unable to decode address");

            let raw_proof = compose_operator_proof(
                receiver_record.nonce as u64,
                &bytes_address,
                &contract_proof.y,
            );
            let ecdsa_proof = sign_ethereum_message(&context.keypair().secret_key, &raw_proof);

            randomness
                .insert(json!({
                    "keyring_id": context.key_id(),
                    "receiver_id": receiver_record.id,
                    "epoch": next_epoch,
                    "alpha":hex::encode(current_alpha.b32()),
                    "gamma": contract_proof.gamma.to_hex_string(),
                    "c":hex::encode(contract_proof.c.b32()),
                    "s":hex::encode(contract_proof.s.b32()),
                    "y":hex::encode(contract_proof.y.b32()),
                    "witness_address": hex::encode(contract_proof.witness_address.b32())[0..40],
                    "witness_gamma": contract_proof.witness_gamma.to_hex_string(),
                    "witness_hash": contract_proof.witness_hash.to_hex_string(),
                    "inverse_z": hex::encode(contract_proof.inverse_z.b32()),
                    "signature_proof": hex::encode(&ecdsa_proof),
                }))
                .await
                .expect("Unable to insert new epoch")
        }
    };

    QuickResponse::res_json(&returning_randomness)
}

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn orand(
    req: Request<hyper::body::Incoming>,
    context: Arc<NodeContext>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let (header, body) = req.into_parts();
    match (&header.method, header.uri.path()) {
        // Handle all post method to JSON RPC
        (&Method::POST, "/") => {
            let max = body.size_hint().upper().unwrap_or(u64::MAX);
            // Body is 64 KB
            if max > 1024 * 64 {
                return QuickResponse::err(node::Error(
                    "PAYLOAD_TOO_LARGE",
                    "Your body too big, can not fit the body bag",
                ));
            }
            // Body to byte
            let whole_body = body
                .collect()
                .await
                .expect("Unable to collect the request body")
                .to_bytes();
            let json_string =
                from_utf8(whole_body.borrow()).expect("Unable to convert body to utf8");
            let json_rpc_payload = match JSONRPCMethod::from_json_string(json_string) {
                Ok(payload) => payload,
                Err(e) => {
                    return QuickResponse::err(e);
                }
            };

            let keyring = context.sqlite().table_keyring();

            let authorized_jwt = match json_rpc_payload {
                JSONRPCMethod::OrandNewEpoch(_, _, _) => {
                    let (jwt_payload, json_web_token) = match header.headers.get("authorization") {
                        Some(e) => match e.to_str() {
                            Ok(s) => match JWT::decode_payload(s) {
                                Ok(p) => (p, s),
                                Err(e) => {
                                    return QuickResponse::err(e);
                                }
                            },
                            Err(_) => {
                                return QuickResponse::err(node::Error(
                                    "INVALID_JWT",
                                    "Unable to decode authorization header",
                                ));
                            }
                        },
                        None => {
                            return QuickResponse::err(node::Error(
                                "INVALID_JWT",
                                "Access denied, this method required authorization",
                            ));
                        }
                    };

                    let user_record = match keyring
                        .find_by_name(jwt_payload.user.clone())
                        .await
                        .expect("Can not query our database")
                    {
                        Some(record) => record,
                        None => {
                            return QuickResponse::err(node::Error(
                                "INVALID_JWT",
                                "Access denied, this method required authorization",
                            ));
                        }
                    };

                    let jwt = JWT::new(&user_record.hmac_secret);
                    if !jwt.verify(json_web_token) {
                        return QuickResponse::err(node::Error(
                            "ACCESS_DENIED",
                            "Access denied, incorrect key",
                        ));
                    }
                    Some(jwt_payload)
                }
                _ => None,
            };

            match json_rpc_payload {
                // Get epoch, it's alias of orand_getPublicEpoch() and orand_getPrivateEpoch()
                JSONRPCMethod::OrandGetEpoch(network, address, epoch) => {
                    orand_get_epoch(network, address, epoch, context).await
                }
                // Get epoch, it's alias of orand_newPublicEpoch() and orand_newPrivateEpoch()
                JSONRPCMethod::OrandNewEpoch(network, address, epoch_id) => match authorized_jwt {
                    Some(jwt_payload) => {
                        // Only orand could able pair with ZERO_ADDRESS
                        if address.eq(ZERO_ADDRESS) && !jwt_payload.user.eq(ORAND_KEYRING_NAME) {
                            return QuickResponse::err(node::Error(
                                "ACCESS_DENIED",
                                "Access denied, you do not have ability to create public epoch",
                            ));
                        }
                        // Create new epoch
                        orand_new_epoch(
                            jwt_payload,
                            network,
                            address,
                            epoch_id,
                            Arc::clone(&context),
                        )
                        .await
                    }
                    None => QuickResponse::err(node::Error(
                        "INVALID_JWT",
                        "Access denied, this method required authorization",
                    )),
                },
                JSONRPCMethod::OrandGetPublicKey(key_name) => {
                    let keyring = context.sqlite().table_keyring();
                    let key_record = keyring
                        .find_by_name(key_name)
                        .await
                        .expect("Can find the given key name");

                    QuickResponse::res_json(&key_record)
                }
                JSONRPCMethod::AdminAddUser(username) => {
                    // Only orand could able pair with ZERO_ADDRESS
                    if authorized_jwt
                        .unwrap_or_default()
                        .user
                        .eq(ORAND_KEYRING_NAME)
                    {
                        match keyring
                            .find_by_name(username.clone())
                            .await
                            .expect("Unable to query user from database")
                        {
                            Some(_) => {
                                return QuickResponse::err(node::Error(
                                    "UNABLE_TO_CREATE_USER",
                                    "Unable to create user",
                                ))
                            }
                            _ => {
                                // Generate hmac key if it didn't exist
                                let mut hmac_secret = [0u8; ORAND_HMAC_KEY_SIZE];
                                random_bytes(&mut hmac_secret);
                                let mut raw_keypair = RawKeyPair::from(KeyPair::new());
                                let insert_result = keyring
                                    .insert(json!({
                                    "username": username,
                                    "hmac_secret": hex::encode(hmac_secret),
                                    "public_key": hex::encode(raw_keypair.public_key), 
                                    "secret_key": hex::encode(raw_keypair.secret_key)}))
                                    .await
                                    .expect("Unable to insert new key to keyring table");
                                // Wipe raw keypair from memory
                                raw_keypair.zeroize();
                                return QuickResponse::res_json(&UserResponse {
                                    username: insert_result.username,
                                    hmac_secret: insert_result.hmac_secret,
                                    public_key: insert_result.public_key,
                                    created_date: insert_result.created_date,
                                });
                            }
                        }
                    }
                    return QuickResponse::err(node::Error(
                        "ACCESS_DENIED",
                        "Access denied, you do not have ability to create public epoch",
                    ));
                }
                JSONRPCMethod::AdminAddReceiver(receiver_name, receiver_address, network) => {
                    // Only orand could able pair with ZERO_ADDRESS
                    if authorized_jwt
                        .unwrap_or_default()
                        .user
                        .eq(ORAND_KEYRING_NAME)
                    {
                        let table_receiver = context.sqlite().table_receiver();
                        match table_receiver
                            .insert(json!({
                                "name": receiver_name,
                                "address": receiver_address,
                                "network": network,
                                "nonce": 0,
                            }))
                            .await
                        {
                            Ok(model_receiver) => return QuickResponse::res_json(&model_receiver),
                            Err(_) => {
                                return QuickResponse::err(node::Error(
                                    "INTERNAL_SERVER_ERROR",
                                    "Unable to add new receiver",
                                ));
                            }
                        }
                    }
                    return QuickResponse::err(node::Error(
                        "ACCESS_DENIED",
                        "Access denied, you do not have ability to create public epoch",
                    ));
                }
                _ => QuickResponse::err(node::Error(
                    "NOT_IMPLEMENTED",
                    "It is not working in this way",
                )),
            }
        }
        _ => QuickResponse::err(node::Error(
            "NOT_IMPLEMENTED",
            "It is not working in this way",
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenv().ok();
    let addr = SocketAddr::from(([0, 0, 0, 0], 1337));
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    let is_testnet = match env::var("ORAND_TESTNET") {
        Ok(s) => s.trim().to_lowercase().eq("true"),
        _ => false,
    };
    // @todo: Move these to another module, we should separate between KEYS and API
    let sqlite = SQLiteDB::new(database_url).await;
    let keyring = sqlite.table_keyring();
    let result_keyring = keyring
        .find_by_name(ORAND_KEYRING_NAME.to_string())
        .await
        .expect("Unable to query keyring table");

    // Create new key if not exist
    let (keyring_record, keypair) = match result_keyring {
        None => {
            // Generate key if it didn't exist
            let mut hmac_secret = [0u8; ORAND_HMAC_KEY_SIZE];
            random_bytes(&mut hmac_secret);
            let new_keypair = match env::var("SECRET_KEY") {
                // Get secret from .env file
                Ok(r) => KeyPair::from(r),
                // Generate new secret
                Err(_) => KeyPair::new(),
            };
            let mut raw_keypair = RawKeyPair::from(new_keypair);
            let insert_result = keyring
                .insert(json!({
                "username": ORAND_KEYRING_NAME,
                "hmac_secret": hex::encode(hmac_secret),
                "public_key": hex::encode(raw_keypair.public_key), 
                "secret_key": hex::encode(raw_keypair.secret_key)}))
                .await
                .expect("Unable to insert new key to keyring table");
            // Wipe raw keypair from memory
            raw_keypair.zeroize();
            (insert_result, new_keypair)
        }
        Some(k) => {
            let secret_key = k.secret_key.clone();
            (k, KeyPair::from(secret_key))
        }
    };

    println!(
        "Public Key: {}",
        hex::encode(keypair.public_key.serialize())
    );
    println!(
        "Address of public key: 0x{}",
        hex::encode(get_address(keypair.public_key))
    );

    // Create new node context
    let node_context = NodeContext::new(keyring_record.id, keypair, is_testnet, sqlite);

    let listener = TcpListener::bind(addr).await?;

    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let ctx = Arc::clone(&node_context);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| orand(req, Arc::clone(&ctx))))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
