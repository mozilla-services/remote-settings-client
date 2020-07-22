use log::{debug, info};
use reqwest::header;
use reqwest::Error as ReqwestError;
use serde::Deserialize;
use serde_json;

pub type KintoObject = serde_json::Value;

#[derive(Deserialize)]
struct KintoPluralResponse {
    data: Vec<KintoObject>,
}

#[derive(Deserialize, Debug)]
pub struct ChangesetResponse {
    pub metadata: KintoObject,
    pub changes: Vec<KintoObject>,
    pub timestamp: u64,
}

#[derive(Debug)]
pub enum KintoError {
    Error { name: String },
}

impl From<ReqwestError> for KintoError {
    fn from(err: ReqwestError) -> Self {
        err.into()
    }
}

impl From<serde_json::error::Error> for KintoError {
    fn from(err: serde_json::error::Error) -> Self {
        err.into()
    }
}

impl From<header::ToStrError> for KintoError {
    fn from(err: header::ToStrError) -> Self {
        err.into()
    }
}

impl From<std::num::ParseIntError> for KintoError {
    fn from(err: std::num::ParseIntError) -> Self {
        err.into()
    }
}

pub async fn get_records(
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
) -> Result<ChangesetResponse, KintoError> {
    let url = format!(
        "{}/buckets/{}/collections/{}/records?_expected={}",
        server, bid, cid, expected
    );
    info!("Fetch {}...", url);
    let resp = reqwest::get(&url).await?;
    let timestamp = resp
        .headers()
        .get("etag")
        .ok_or_else(|| KintoError::Error {
            name: "no ETag error".to_owned(),
        })?;

    debug!("Timestamp : {:?}", timestamp);

    let size = resp.headers().get("content-length").ok_or_else(|| -1);
    debug!("Download {:?} bytes...", size);
    let body = resp.text().await?;
    let result: ChangesetResponse = serde_json::from_str(&body)?;

    Ok(result)
}

pub async fn get_changeset(
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
) -> Result<ChangesetResponse, KintoError> {
    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}",
        server, bid, cid, expected
    );
    info!("Fetch {}...", url);
    let resp = reqwest::get(&url).await?;

    let size: i64 = match resp.headers().get("content-length").ok_or_else(|| -1) {
        Ok(val) => val.to_str()?.parse()?,
        Err(default) => default,
    };
    debug!("Download {:?} bytes...", size);

    let body = resp.text().await?;
    let result: ChangesetResponse = serde_json::from_str(&body)?;

    Ok(result)
}
