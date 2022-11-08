// #![deny(warnings)]

use bytes::Bytes;
use dotenv::dotenv;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Body;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use orochimaru::sqlitedb::SqliteDB;
use serde_json::json;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn orand(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(full(
            "Try POSTing data to /echo such as: `curl localhost:3000/echo -XPOST -d 'hello world'`",
        ))),

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body().boxed())),

        // TODO: Fix this, broken in PR #2896
        // Convert to uppercase before sending back to client using a stream.
        // (&Method::POST, "/echo/uppercase") => {
        // let chunk_stream = req.into_body().map_ok(|chunk| {
        //     chunk
        //         .iter()
        //         .map(|byte| byte.to_ascii_uppercase())
        //         .collect::<Vec<u8>>()
        // });
        // Ok(Response::new(Body::wrap_stream(chunk_stream)))
        // }

        // Reverse the entire body before sending back to the client.
        //
        // Since we don't know the end yet, we can't simply stream
        // the chunks as they arrive as we did with the above uppercase endpoint.
        // So here we do `.await` on the future, waiting on concatenating the full body,
        // then afterwards the content can be reversed. Only then can we return a `Response`.
        (&Method::POST, "/echo/reversed") => {
            // To protect our server, reject requests with bodies larger than
            // 64kbs of data.
            let max = req.body().size_hint().upper().unwrap_or(u64::MAX);
            if max > 1024 * 64 {
                let mut resp = Response::new(full("Body too big"));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                return Ok(resp);
            }

            let whole_body = req.collect().await?.to_bytes();

            let reversed_body = whole_body.iter().rev().cloned().collect::<Vec<u8>>();
            Ok(Response::new(full(reversed_body)))
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
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
    let sqlite = SqliteDB::new(database_url).await;
    println!(
        "{:?}",
        json!({"public_key": "Public key".to_string(), "secret_key":"Secret key".to_string()})
    );
    sqlite
        .keyring_insert(
            json!({"public_key": "Public key".to_string(), "secret_key":"Secret key".to_string()}),
        )
        .await
        .unwrap();

    println!("{:?}", sqlite.keyring_find_all().await?);

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
