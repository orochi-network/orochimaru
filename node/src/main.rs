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
    helper::{get_address, random_bytes},
    KeyPair, RawKeyPair, Zeroable,
};
use node::{
    jwt::JWT,
    postgres_sql::Postgres,
    rpc::{JSONRPCMethod, ZERO_ADDRESS},
    NodeContext, QuickResponse,
};
use sea_orm::prelude::DateTime;
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
    /// HMAC secret
    pub hmac_secret: String,
    /// Public key
    pub public_key: String,
    /// Created date
    pub created_date: DateTime,
}

async fn orand_get_epoch(
    network: i64,
    address: String,
    epoch: i64,
    context: Arc<NodeContext<'_>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let postgres = context.postgres();
    let randomness = postgres.table_randomness();

    if epoch == i64::MAX {
        match randomness.find_recent_epoch(network, &address).await {
            Ok(recent_epochs) => QuickResponse::res_json(&recent_epochs),
            Err(_) => QuickResponse::err(node::Error("NOT_FOUND", "Epoch was not found")),
        }
    } else {
        match randomness
            .find_closure_epoch(network, &address, epoch)
            .await
        {
            Ok(recent_epochs) => QuickResponse::res_json(&recent_epochs),
            Err(_) => QuickResponse::err(node::Error("NOT_FOUND", "Epoch was not found")),
        }
    }
}

async fn orand_new_epoch(
    context: Arc<NodeContext<'_>>,
    username: String,
    network: i64,
    address: String,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let postgres = context.postgres();
    let randomness = postgres.table_randomness();

    match randomness
        .safe_insert(Arc::clone(&context), username, network, address)
        .await
    {
        Ok(randomness_returning_record) => QuickResponse::res_json(&randomness_returning_record),
        Err(_) => QuickResponse::err(node::Error("INTERNAL_SERVER_ERROR", "Unknown error")),
    }
}

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn orand(
    req: Request<hyper::body::Incoming>,
    context: Arc<NodeContext<'_>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let (header, body) = req.into_parts();
    match (&header.method, header.uri.path()) {
        // Handle all post method to JSON RPC
        //(&Method::OPTIONS, "/") => QuickResponse::option(),
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

            log::debug!(
                "Request: {} {} {} ",
                &header.method,
                header.uri.path(),
                &json_string,
            );

            let keyring = context.postgres().table_keyring();
            let receiver = context.postgres().table_receiver();

            let authorized_jwt = {
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
            };

            let jwt_payload = match authorized_jwt {
                Some(p) => p,
                None => {
                    return QuickResponse::err(node::Error(
                        "INVALID_JWT",
                        "Access denied, this method required authorization",
                    ));
                }
            };

            match json_rpc_payload {
                // Get epoch, it's alias of orand_getPublicEpoch() and orand_getPrivateEpoch()
                JSONRPCMethod::OrandGetEpoch(network, address, epoch) => {
                    orand_get_epoch(network, address, epoch, context).await
                }
                // Get epoch, it's alias of orand_newPublicEpoch() and orand_newPrivateEpoch()
                JSONRPCMethod::OrandNewEpoch(network, address) => {
                    // Only orand could able pair with ZERO_ADDRESS
                    if address.eq(ZERO_ADDRESS) && !jwt_payload.user.eq(ORAND_KEYRING_NAME) {
                        return QuickResponse::err(node::Error(
                            "ACCESS_DENIED",
                            "Access denied, you do not have ability to create public epoch",
                        ));
                    }
                    // Create new epoch
                    orand_new_epoch(
                        Arc::clone(&context),
                        jwt_payload.user.clone(),
                        network,
                        address,
                    )
                    .await
                }
                JSONRPCMethod::OrandGetPublicKey(key_name) => {
                    let keyring = context.postgres().table_keyring();
                    let key_record = keyring
                        .find_by_name(key_name)
                        .await
                        .expect("Can find the given key name");

                    QuickResponse::res_json(&key_record)
                }
                JSONRPCMethod::AdminAddUser(username) => {
                    // Only orand could able pair with ZERO_ADDRESS
                    if jwt_payload.user.eq(ORAND_KEYRING_NAME) {
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
                                let mut raw_keypair = RawKeyPair::from(&KeyPair::new());
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
                    QuickResponse::err(node::Error(
                        "ACCESS_DENIED",
                        "Access denied, you do not have ability add new user",
                    ))
                }
                JSONRPCMethod::AdminAddReceiver(username, receiver_address, network) => {
                    // Only orand could able pair with ZERO_ADDRESS
                    if jwt_payload.user.eq(ORAND_KEYRING_NAME) {
                        let model_keyring = match context
                            .postgres()
                            .table_keyring()
                            .find_by_name(username.clone())
                            .await
                            .expect("User must existed in the database")
                        {
                            Some(keyring_record) => keyring_record,
                            None => {
                                return QuickResponse::err(node::Error(
                                    "ACCESS_DENIED",
                                    "User may not exist or database error",
                                ));
                            }
                        };
                        let receiver_check = receiver
                            .find_one(network, &receiver_address)
                            .await
                            .expect("Unable to query receiver from database");
                        // Dummy patch to check if receiver existed
                        if receiver_check.is_some() {
                            return QuickResponse::res_json(&receiver_check);
                        }

                        log::info!(
                            "Trying insert new receiver address: {} network: {}",
                            receiver_address,
                            network
                        );
                        match receiver
                            .insert(json!({
                                "keyring_id": model_keyring.id,
                                "name": Uuid::new_v4().to_string(),
                                "address": receiver_address,
                                "network": network,
                                "nonce": 0,
                            }))
                            .await
                        {
                            Ok(model_receiver) => return QuickResponse::res_json(&model_receiver),
                            Err(err) => {
                                log::error!("Unable to add new receiver {}", err);
                                return QuickResponse::err(node::Error(
                                    "INTERNAL_SERVER_ERROR",
                                    "Unable to add new receiver",
                                ));
                            }
                        }
                    }
                    QuickResponse::err(node::Error(
                        "ACCESS_DENIED",
                        "Access denied, you do not have ability to add new receiver",
                    ))
                }
                JSONRPCMethod::AdminGetUser(username) => {
                    if jwt_payload.user.eq(ORAND_KEYRING_NAME) {
                        match keyring
                            .find_by_name(username.clone())
                            .await
                            .expect("Unable to query user from database")
                        {
                            Some(record) => {
                                return QuickResponse::res_json(&json!({
                                    "username": record.username,
                                    "hmac_secret": record.hmac_secret,
                                    "created_date": record.created_date
                                }));
                            }
                            _ => {
                                return QuickResponse::err(node::Error(
                                    "ACCESS_DENIED",
                                    "User may not exist or database error",
                                ))
                            }
                        }
                    }
                    QuickResponse::err(node::Error(
                        "ACCESS_DENIED",
                        "Access denied, you do not have ability to add new receiver",
                    ))
                }
                JSONRPCMethod::AdminGetReceiver(username) => QuickResponse::res_json(
                    &receiver
                        .find_by_username(username.clone())
                        .await
                        .expect("Unable to query user from database"),
                ),
                JSONRPCMethod::AdminRemoveReceiver(username, receiver_id) => {
                    let result = receiver.delete(username, receiver_id).await;
                    match result {
                        Ok(_) => QuickResponse::res_json(
                            &json!({"success": true, "message": "Receiver has been removed"}),
                        ),
                        Err(_) => QuickResponse::err(node::Error(
                            "INTERNAL_SERVER_ERROR",
                            "Unable to remove receiver",
                        )),
                    }
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
    env_logger::init();
    let addr = SocketAddr::from(([0, 0, 0, 0], 1337));
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    let is_testnet = match env::var("ORAND_TESTNET") {
        Ok(s) => s.trim().to_lowercase().eq("true"),
        _ => false,
    };
    // @todo: Move these to another module, we should separate between KEYS and API
    let postgres = Postgres::new(database_url).await;
    let keyring = postgres.table_keyring();
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
            let mut raw_keypair = RawKeyPair::from(&new_keypair);
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

    log::info!(
        "Public Key: {}",
        hex::encode(keypair.public_key.serialize())
    );
    log::info!(
        "Address of public key: 0x{}",
        hex::encode(get_address(&keypair.public_key))
    );

    // Create new node context
    let node_context = NodeContext::new(keyring_record.id, keypair, is_testnet, postgres);

    let listener = TcpListener::bind(addr).await?;

    log::info!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let ctx = Arc::clone(&node_context);
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| orand(req, Arc::clone(&ctx))))
                .await
            {
                log::error!("Error serving connection: {:?}", err);
            }
        });
    }
}
