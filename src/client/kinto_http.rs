/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::{debug, info};
use serde::Deserialize;
use serde_json;
use url::{ParseError, Url};
use viaduct::{Error as ViaductError, Request};

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

pub fn get_records(
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

    let resp = Request::get(Url::parse(&url)?).send()?;
    let timestamp = resp.headers.get("etag").ok_or_else(|| KintoError::Error {
        name: "no ETag error".to_owned(),
    })?;

    debug!("Timestamp : {:?}", timestamp);

    let size = resp
        .headers
        .get("content-length")
        .ok_or_else(|| KintoError::Error {
            name: "no content-length header error".to_owned(),
        });
    debug!("Download {:?} bytes...", size);
    let result: ChangesetResponse = resp.json()?;

    Ok(result)
}

pub fn get_changeset(
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

    let resp = Request::get(Url::parse(&url)?).send()?;

    info!("The response is {:?}", resp);
    let size = resp
        .headers
        .get("content-length")
        .ok_or_else(|| KintoError::Error {
            name: "no content-length header error".to_owned(),
        })?;
    debug!("Download {:?} bytes...", size);

    let result: ChangesetResponse = resp.json()?;

    Ok(result)
}
