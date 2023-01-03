#![deny(warnings)]

use bytes::Bytes;
use dotenv::dotenv;
use ecvrf::{
    helper::{generate_raw_keypair, get_address, random_bytes, recover_raw_keypair},
    secp256k1::{curve::Scalar, PublicKey, SecretKey},
    ECVRF,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Body,
    server::conn::http1,
    service::service_fn,
    {Method, Request, Response, StatusCode},
};
use orochimaru::{
    ethereum::{compose_operator_proof, sign_ethereum_message},
    json_rpc::JSONRPCMethod,
    sqlite_db::SQLiteDB,
};
use serde_json::json;
use std::{borrow::Borrow, env, net::SocketAddr, str::from_utf8};
use tokio::net::TcpListener;

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn orand(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    // TODO Move these to another module, we should separate between KEYS and API
    let sqlite: SQLiteDB = SQLiteDB::new(database_url).await;
    let keyring = sqlite.table_keyring();
    let randomness = sqlite.table_randomness();
    let receiver = sqlite.table_receiver();

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

        // Handle all post method to JSON RPC
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
                // Get epoch, it's alias of orand_getPublicEpoch() and orand_getPrivateEpoch()
                JSONRPCMethod::OrandGetEpoch(network, address, epoch) => {
                    let recent_epochs = randomness
                        .find_recent_epoch(network, address, epoch)
                        .await
                        .expect("Can not get recent epoch");

                    let serialized_result = serde_json::to_string_pretty(&recent_epochs)
                        .expect("Can not serialize data");
                    Ok(Response::new(full(serialized_result)))
                }
                // Get epoch, it's alias of orand_newPublicEpoch() and orand_newPrivateEpoch()
                JSONRPCMethod::OrandNewEpoch(network, address) => {
                    let latest_epoch_record = randomness
                        .find_latest_epoch(network, address.clone())
                        .await
                        .unwrap();

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

                    let returning_receiver = receiver
                        .update(network, address.clone())
                        .await
                        .expect("Unable to update receiver")
                        .expect("Data was insert but not found, why?");
                    let bytes_address: [u8; 20] =
                        hex::decode(address.replace("0x", "").replace("0X", ""))
                            .expect("Unable to decode address")
                            .as_slice()
                            .try_into()
                            .unwrap();
                    let raw_proof = compose_operator_proof(
                        returning_receiver.nonce as u64,
                        &bytes_address,
                        contract_proof.y,
                    );
                    let ecdsa_proof = sign_ethereum_message(&secret_key, &raw_proof);
                    let returning_randomness = randomness
                        .insert_returning(json!({
                            "keyring_id": keyring_record.id,
                            "receiver_id": returning_receiver.id,
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
                            "signature_proof": hex::encode(&ecdsa_proof),
                        }))
                        .await
                        .unwrap();
                    let serialized_result =
                        serde_json::to_string_pretty(&returning_randomness).unwrap();
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
                _ => Ok(Response::new(full(
                    "{\"success\": \"false\", \"message\": \"It is not working in this way\"}",
                ))),
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
    let addr = SocketAddr::from(([0, 0, 0, 0], 1337));
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    let sqlite: SQLiteDB = SQLiteDB::new(database_url).await;
    let keyring = sqlite.table_keyring();
    let result_keyring = keyring.find_by_name("chiro".to_string()).await.unwrap();
    let receiver = sqlite.table_receiver();
    receiver.get_latest_record(1, "".to_string()).await?;
    // Create new key if not exist
    let pk = match result_keyring {
        None => {
            // Generate key if it didn't exist
            let mut hmac_secret = [0u8; 16];
            random_bytes(&mut hmac_secret);
            let new_keypair = match env::var("SECRET_KEY") {
                // Get secret from .env file
                Ok(r) => recover_raw_keypair(
                    hex::decode(r.trim())
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                ),
                // Generate new secret
                Err(_) => generate_raw_keypair(),
            };
            keyring
                .insert(json!({
                "username": "chiro",
                "hmac_secret": hex::encode(hmac_secret),
                "public_key": hex::encode(new_keypair.public_key), 
                "secret_key": hex::encode(new_keypair.secret_key)}))
                .await
                .expect("Unable to insert new key to keyring table");
            PublicKey::parse(&new_keypair.public_key).expect("Wrong public key format")
        }
        Some(k) => PublicKey::parse(
            hex::decode(k.public_key)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .expect("Wrong public key format"),
    };

    println!("Public Key: {}", hex::encode(pk.serialize()));
    println!("Address of public key: 0x{}", hex::encode(get_address(pk)));

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
