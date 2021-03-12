/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::{debug, info};
use serde::{Deserialize, Serialize};
use url::{ParseError, Url};
use viaduct::{Error as ViaductError, Request};

pub type KintoObject = serde_json::Value;

#[derive(Deserialize, Debug)]
struct KintoPluralResponse<T> {
    data: Vec<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChangesetResponse {
    pub metadata: KintoObject,
    pub changes: Vec<KintoObject>,
    pub timestamp: u64,
}

#[derive(Debug)]
pub enum KintoError {
    ClientError { name: String },
    ServerError { name: String },
}

impl From<ViaductError> for KintoError {
    fn from(err: ViaductError) -> Self {
        info!("Viaduct error {}", err);
        KintoError::ClientError {
            name: format!("Viaduct error: {}", err),
        }
    }
}

impl From<serde_json::error::Error> for KintoError {
    fn from(err: serde_json::error::Error) -> Self {
        info!("JSON error: {}", err);
        KintoError::ServerError {
            name: format!("JSON error: {}", err),
        }
    }
}

impl From<ParseError> for KintoError {
    fn from(err: ParseError) -> Self {
        info!("Parse error: {}", err);
        KintoError::ClientError {
            name: format!("Parse error: {}", err),
        }
    }
}

pub fn get_latest_change_timestamp(server: &str, bid: &str, cid: &str) -> Result<u64, KintoError> {
    let response = get_changeset(&server, "monitor", "changes", None)?;
    let change = response
        .changes
        .iter()
        .find(|&x| x["bucket"] == bid && x["collection"] == cid)
        .ok_or(KintoError::ClientError {
            name: format!("Unknown collection {}/{}", bid, cid),
        })?;

    let last_modified = change["last_modified"]
        .as_u64()
        .ok_or(KintoError::ServerError {
            name: format!("Bad server timestamp: {}", change["last_modified"]),
        })?;

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
    let cache_bust = expected.unwrap_or(0);
    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}",
        server, bid, cid, cache_bust
    );
    info!("Fetch {}...", url);

    let resp = Request::get(Url::parse(&url)?).send()?;

    info!("The response is {:?}", resp);

    let size: i64 = match resp.headers.get("content-length") {
        Some(val) => val.parse().unwrap_or(-1),
        None => -1,
    };

    debug!("Download {:?} bytes...", size);

    let result: ChangesetResponse = resp.json()?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{get_latest_change_timestamp, KintoError};
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _ = set_backend(&ReqwestBackend);
    }

    #[test]
    fn test_fetch() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");
        let mock_body = r#"{
            "metadata": {},
            "changes": [
                {
                    "id": "123",
                    "last_modified": 9173,
                    "bucket":"main",
                    "collection":"url-classifier-skip-urls",
                    "host":"localhost:5000"
                }
            ],
            "timestamp": 42
        }"#;

        let mut get_latest_change_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/monitor/collections/changes/changeset")
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(mock_body)
            .create_on(&mock_server);

        let res =
            get_latest_change_timestamp(&mock_server_address, "main", "url-classifier-skip-urls")
                .unwrap();

        assert_eq!(res, 9173);

        get_latest_change_mock.delete();
    }

    #[test]
    fn test_bad_url() {
        init();

        let err =
            get_latest_change_timestamp("%^", "main", "url-classifier-skip-urls").unwrap_err();
        match err {
            KintoError::ClientError { name } => {
                assert_eq!(name, "Parse error: relative URL without a base")
            }
            _ => assert!(false),
        };
    }

    #[test]
    fn test_bad_json() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");
        let mock_body = r#"{
            "met :
        }"#;

        let mut get_latest_change_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/monitor/collections/changes/changeset")
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(mock_body)
            .create_on(&mock_server);

        let err =
            get_latest_change_timestamp(&mock_server_address, "main", "url-classifier-skip-urls")
                .unwrap_err();

        match err {
            KintoError::ServerError { name } => {
                assert!(name.contains("JSON error: control character"))
            }
            _ => assert!(false),
        };

        get_latest_change_mock.delete();
    }

    #[test]
    fn test_bad_timestamp() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");
        let mock_body = r#"{
            "metadata": {},
            "changes": [
                {
                    "id": "123",
                    "last_modified": "foo",
                    "bucket":"main",
                    "collection":"url-classifier-skip-urls",
                    "host":"localhost:5000"
                }
            ],
            "timestamp": 42
        }"#;

        let mut get_latest_change_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/monitor/collections/changes/changeset")
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(mock_body)
            .create_on(&mock_server);

        let err =
            get_latest_change_timestamp(&mock_server_address, "main", "url-classifier-skip-urls")
                .unwrap_err();

        match err {
            KintoError::ServerError { name } => assert_eq!(name, "Bad server timestamp: \"foo\""),
            _ => assert!(false),
        };

        get_latest_change_mock.delete();
    }
}
