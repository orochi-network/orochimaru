#![deny(warnings)]

use bytes::Bytes;
use dotenv::dotenv;
use ecvrf::ECVRF;
use ecvrf::{
    helper::{generate_raw_keypair, get_address, random_bytes},
    secp256k1::{curve::Scalar, PublicKey, SecretKey},
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Body,
    server::conn::http1,
    service::service_fn,
    {Method, Request, Response, StatusCode},
};
use orochimaru::ethereum::ethereum::{compose_operator_proof, sign_ethereum_message};
use orochimaru::json_rpc::JSONRPCMethod;
use orochimaru::sqlitedb::SqliteDB;
use serde_json::json;
use std::borrow::Borrow;
use std::env;
use std::net::SocketAddr;
use std::str::from_utf8;
use tokio::net::TcpListener;

const CHAIN_ID_BNB: u32 = 56;

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn orand(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    // TODO Move these to another module, we should separate between KEYS and API
    let sqlite: SqliteDB = SqliteDB::new(database_url).await;
    let keyring = sqlite.table_keyring().await;
    let randomness = sqlite.table_randomness().await;

    // Reconstruct secret key from database
    let keyring_record = keyring
        .find_by_name("chiro".to_string())
        .await
        .expect("Can not query our database")
        .expect("Chiro not found");

    let secret_key = SecretKey::parse(
        hex::decode(keyring_record.secret_key)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    )
    .expect("Can not reconstruct secret key");

    let vrf = ECVRF::new(secret_key);

    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(full("Wrong method, you know!."))),

        // Simply echo the body back to the client.
        (&Method::POST, "/") => {
            let max = req.body().size_hint().upper().unwrap_or(u64::MAX);
            if max > 1024 * 64 {
                let mut resp = Response::new(full("Your body too big, can not fit the body bag"));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                return Ok(resp);
            }
            // Body to byte
            let whole_body = req.collect().await?.to_bytes();
            let json_string = from_utf8(whole_body.borrow()).unwrap();
            let json_rpc_payload = JSONRPCMethod::from_json_string(json_string);

            match json_rpc_payload {
                // We ignore network param right now, support BNB chain first
                JSONRPCMethod::OrandGetPublicEpoch(_, epoch) => {
                    let recent_epochs = randomness
                        .find_recent_epoch(epoch)
                        .await
                        .expect("Can not get recent epoch");

                    let serialized_result = serde_json::to_string_pretty(&recent_epochs)
                        .expect("Can not serialize data");
                    Ok(Response::new(full(serialized_result)))
                }
                JSONRPCMethod::OrandNewEpoch(_) => {
                    let latest_epoch_record =
                        randomness.find_latest_epoch(CHAIN_ID_BNB).await.unwrap();

                    let (current_alpha, next_epoch) = match latest_epoch_record {
                        Some(latest_epoch) => {
                            let mut alpha = Scalar::default();
                            // Alpha of current epoch is previous randomness
                            alpha
                                .set_b32(
                                    &hex::decode(latest_epoch.y)
                                        .unwrap()
                                        .as_slice()
                                        .try_into()
                                        .unwrap(),
                                )
                                .unwrap_u8();
                            (alpha, latest_epoch.epoch + 1)
                        }
                        None => {
                            // Get alpha from random entropy
                            let mut buf = [0u8; 32];
                            random_bytes(&mut buf);
                            let mut alpha = Scalar::default();
                            alpha.set_b32(&buf).unwrap_u8();
                            (alpha, 0)
                        }
                    };

                    let contract_proof = vrf.prove_contract(&current_alpha);

                    let gamma =
                        [contract_proof.gamma.x.b32(), contract_proof.gamma.y.b32()].concat();
                    let witness_gamma = [
                        contract_proof.witness_gamma.x.b32(),
                        contract_proof.witness_gamma.y.b32(),
                    ]
                    .concat();

                    let witness_hash = [
                        contract_proof.witness_hash.x.b32(),
                        contract_proof.witness_hash.y.b32(),
                    ]
                    .concat();

                    let insert_result = randomness
                        .insert_returning(json!({
                            "network": CHAIN_ID_BNB,
                            "keyring_id": keyring_record.id,
                            "epoch": next_epoch,
                            "alpha":hex::encode(current_alpha.b32()),
                            "gamma":hex::encode(&gamma),
                            "c":hex::encode(&contract_proof.c.b32()),
                            "s":hex::encode(&contract_proof.s.b32()),
                            "y":hex::encode(&contract_proof.y.b32()),
                            "witness_address": hex::encode(contract_proof.witness_address.b32())[24..64],
                            "witness_gamma": hex::encode(&witness_gamma),
                            "witness_hash": hex::encode(&witness_hash),
                            "inverse_z": hex::encode(contract_proof.inverse_z.b32()),
                        }))
                        .await
                        .unwrap();
                    let serialized_result = serde_json::to_string_pretty(&insert_result).unwrap();
                    Ok(Response::new(full(serialized_result)))
                }
                JSONRPCMethod::OrandGetPublicKey(key_name) => {
                    let key_record = keyring
                        .find_by_name(key_name)
                        .await
                        .expect("Can find the given key name");

                    let serialized_result =
                        serde_json::to_string_pretty(&key_record).expect("Can not serialize data");
                    Ok(Response::new(full(serialized_result)))
                }
            }
        }

        // Return the 403 Forbidden for other routes.
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::FORBIDDEN;
            Ok(not_found)
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenv().ok();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    let sqlite: SqliteDB = SqliteDB::new(database_url).await;
    let keyring = sqlite.table_keyring().await;
    let result_keyring = keyring.find_by_name("chiro".to_string()).await.unwrap();

    // Create new key if not exist
    match result_keyring {
        None => {
            // Generate key if it didn't exist
            let mut hmac_secret = [0u8; 16];
            random_bytes(&mut hmac_secret);
            let new_keypair = generate_raw_keypair();
            keyring
                .insert(json!({
                "username": "chiro",
                "hmac_secret": hex::encode(hmac_secret),
                "public_key": hex::encode(new_keypair.public_key), 
                "secret_key": hex::encode(new_keypair.secret_key)}))
                .await
                .unwrap();
        }
        Some(k) => {
            println!("Found chiro key!");
            println!("Secret key: {}", k.secret_key);
            println!("Public Key: {}", k.public_key);
            let secret_key = SecretKey::parse(
                hex::decode(k.secret_key)
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
            let public_key = PublicKey::from_secret_key(&secret_key);
            println!(
                "Address of public key: {}",
                hex::encode(get_address(public_key))
            );

            let raw_proof = compose_operator_proof(2, &[0xabu8; 20], Scalar::from_int(64));
            println!("{}", hex::encode(&raw_proof));
            println!(
                "{}",
                hex::encode(sign_ethereum_message(&secret_key, &raw_proof))
            );
        }
    };

    let listener = TcpListener::bind(addr).await?;

    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(stream, service_fn(orand))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
