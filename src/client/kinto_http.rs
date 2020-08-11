/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::{debug, info};
use serde::Deserialize;
use serde_json;
use url::{ParseError, Url};
use viaduct::{Error as ViaductError, Request};

pub type KintoObject = serde_json::Value;

#[derive(Deserialize, Debug)]
struct KintoPluralResponse<T> {
    data: Vec<T>,
}

#[derive(Deserialize, Debug)]
pub struct ChangesetResponse {
    pub metadata: KintoObject,
    pub changes: Vec<KintoObject>,
    pub timestamp: u64,
}

#[derive(Deserialize, Debug)]
pub struct LatestChangeResponse {
    pub id: String,
    pub last_modified: u64,
    pub bucket: String,
    pub collection: String,
    pub host: String,
}

#[derive(Debug)]
pub enum KintoError {
    Error { name: String },
}

impl From<ViaductError> for KintoError {
    fn from(err: ViaductError) -> Self {
        info!("Viaduct error {}", err);
        err.into()
    }
}

impl From<serde_json::error::Error> for KintoError {
    fn from(err: serde_json::error::Error) -> Self {
        err.into()
    }
}

impl From<ParseError> for KintoError {
    fn from(err: ParseError) -> Self {
        info!("Parse error {}", err);
        err.into()
    }
}

impl From<std::num::ParseIntError> for KintoError {
    fn from(err: std::num::ParseIntError) -> Self {
        err.into()
    }
}

pub fn get_latest_change_timestamp(server: &str, bid: &str, cid: &str) -> Result<u64, KintoError> {
    let url = format!(
        "{}/buckets/monitor/collections/changes/records?bucket={}&collection={}",
        server, bid, cid
    );

    info!("Fetch latest change {}...", url);
    let resp = Request::get(Url::parse(&url)?).send()?;

    let size = resp
        .headers
        .get("content-length")
        .ok_or_else(|| KintoError::Error {
            name: "no content-length header error".to_owned(),
        });
    debug!("Download {:?} bytes...", size);

    let latest_change: KintoPluralResponse<LatestChangeResponse> = resp.json()?;
    
    let last_modified = match latest_change.data.get(0) {
        Some(change) => change.last_modified,
        None => {
            // bucket/collection provided is unknown
            return Err(KintoError::Error {name: format!("Unknown collection {}/{}", bid, cid)});
        }
    };

    debug!(
        "collection: {}, bucket: {}, last_modified: {}",
        cid, bid, last_modified
    );

    Ok(last_modified)
}

pub fn get_changeset(
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
) -> Result<ChangesetResponse, KintoError> {
    debug!(
        "The expected timestamp for bucket={}, collection={} is {}",
        bid, cid, expected
    );

    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}",
        server, bid, cid, expected
    );
    info!("Fetch {}...", url);

    let resp = Request::get(Url::parse(&url)?).send()?;

    info!("The response is {:?}", resp);

    let size: i64 = match resp.headers.get("content-length").ok_or_else(|| -1) {
        Ok(val) => val.parse()?,
        Err(default) => default,
    };

    debug!("Download {:?} bytes...", size);

    let result: ChangesetResponse = resp.json()?;

    Ok(result)
}
