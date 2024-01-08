use crate::Error;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{Response, StatusCode};
use serde::Serialize;

/// Empty response
pub fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Full response
pub fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn json_encode<T>(value: &T) -> Result<String, Error>
where
    T: ?Sized + Serialize,
{
    match serde_json::to_string_pretty(value) {
        Ok(s) => Ok(s),
        Err(_) => Err(Error("SERIALIZE_ERROR", "Can not serialize data")),
    }
}

/// Quick response
pub struct QuickResponse;

impl QuickResponse {
    /// Invoke quick response with status 400
    pub fn err(err: Error) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        Ok(Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Content-Type", "application/json")
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(full(err.to_json_string()))
            .expect("Unable to construct response"))
    }

    /// Invoke quick response with status 200
    pub fn ok<B: Into<Bytes>>(
        body: B,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        Ok(Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Content-Type", "application/json")
            .status(StatusCode::OK)
            .body(full(body))
            .expect("Unable to construct response"))
    }

    /// Response based on result
    pub fn res<B: Into<Bytes>>(
        ret: Result<B, Error>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        match ret {
            Ok(body) => Self::ok(body),
            Err(err) => Self::err(err),
        }
    }

    /// Response based on result
    pub fn res_json<J: ?Sized + Serialize>(
        value: &J,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        Self::res(json_encode(value))
    }
}
