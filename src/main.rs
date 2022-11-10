// #![deny(warnings)]

use bytes::Bytes;
use dotenv::dotenv;
use ecvrf::helper::{generate_raw_keypair, random_bytes};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Body;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use orochimaru::json_rpc::JSONRPCMethod;
use orochimaru::sqlitedb::SqliteDB;
use serde_json::json;
use std::borrow::Borrow;
use std::env;
use std::net::SocketAddr;
use std::str::from_utf8;
use tokio::net::TcpListener;

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

    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(full("Wrong method, you know!."))),

        // Simply echo the body back to the client.
        (&Method::POST, "/") => {
            let max = req.body().size_hint().upper().unwrap_or(u64::MAX);
            if max > 1024 * 64 {
                let mut resp = Response::new(full("Body too big"));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                return Ok(resp);
            }
            // Body to byte
            let whole_body = req.collect().await?.to_bytes();
            let json_string = from_utf8(whole_body.borrow()).unwrap();
            let json_rpc_payload = JSONRPCMethod::from_json_string(json_string);
            match json_rpc_payload {
                JSONRPCMethod::OrandGetPublicEpoch(network, epoch) => {}
                JSONRPCMethod::OrandNewEpoch(network) => {}
            }
            // serde_json::to_string(value)
            Ok(Response::new(full(whole_body)))
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
        _ => {}
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
