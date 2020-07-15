use serde::Deserialize;
use serde_json;
use reqwest::Error as ReqwestError;
use reqwest::header as header;
use log::{debug, info};

pub type KintoObject = serde_json::Value;

#[derive(Deserialize, Debug)]
struct KintoPluralResponse<T> {
    data: Vec<T>,
}

#[derive(Deserialize)]
#[derive(Debug)]
pub struct ChangesetResponse {
    pub metadata: KintoObject,
    pub changes: Vec<KintoObject>,
    pub timestamp: u64,
}

#[derive(Deserialize)]
#[derive(Debug)]
pub struct LatestChangeResponse {
    pub id: String,
    pub last_modified: u64,
    pub bucket: String,
    pub collection: String,
    pub host: String
}

#[derive(Debug)]
pub enum KintoError {
    Error {name: String}
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

pub async fn get_last_modified_change(
    server: &str,
    bid: &str,
    cid: &str,
) -> Result<u64, KintoError> {
    let url = format!(
        "{}/buckets/monitor/collections/changes/records?bucket={}&collection={}",
        server, bid, cid
    );

    info!("Fetch latest change {}...", url);
    let resp = reqwest::get(&url).await?;

    let timestamp = resp
        .headers()
        .get("etag").ok_or_else(|| KintoError::Error {name: "no ETag error".to_owned()})?;

    debug!("Timestamp : {:?}", timestamp);

    let size = resp.headers().get("content-length").ok_or_else(|| -1);
    debug!("Download {:?} bytes...", size);
    
    let body = resp.text().await?;

    let latest_change: KintoPluralResponse<LatestChangeResponse> = serde_json::from_str(&body)?;
    
    let last_modified = match latest_change.data.get(0) {
        Some(change) => change.last_modified,
        _ => 0 // 0 by default
    };

    debug!("collection {}, bucket {}, last modified timestamp {}", cid, bid, last_modified);

    Ok(last_modified)
}

pub async fn get_changeset(
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
) -> Result<ChangesetResponse, KintoError> {

    debug!("The expected value for bucket={}, collection={} is {}", bid, cid, expected);

    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}",
        server, bid, cid, expected
    );
    info!("Fetch {}...", url);
    let resp = reqwest::get(&url).await?;

    let size: i64 = match resp.headers().get("content-length").ok_or_else(|| -1) {
        Ok(val) => val.to_str()?.parse()?,
        Err(default) => {
            default
        }
    };
    debug!("Download {:?} bytes...", size);

    let body = resp.text().await?;
    let result: ChangesetResponse = serde_json::from_str(&body)?;

    Ok(result)
}
