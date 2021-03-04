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
        info!("JSON error: {}", err);
        KintoError::Error {
            name: format!("JSON error {}", err),
        }
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
        info!("Parse error {}", err);
        err.into()
    }
}

pub fn get_latest_change_timestamp(server: &str, bid: &str, cid: &str) -> Result<u64, KintoError> {
    let response = get_changeset(&server, "monitor", "changes", None)?;
    let change = match response
        .changes
        .iter()
        .find(|&x| x["bucket"] == bid && x["collection"] == cid)
    {
        Some(v) => v,
        None => {
            // bucket/collection provided is unknown
            return Err(KintoError::Error {
                name: format!("Unknown collection {}/{}", bid, cid),
            });
        }
    };
    let last_modified = change["last_modified"].as_u64().unwrap();

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
    expected: Option<u64>,
) -> Result<ChangesetResponse, KintoError> {
    debug!(
        "The expected timestamp for bucket={}, collection={} is {:?}",
        bid, cid, expected
    );
    let cache_bust = match expected {
        Some(v) => v,
        None => 0
    };
    let url = format!("{}/buckets/{}/collections/{}/changeset?_expected={}", server, bid, cid, cache_bust);
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
