/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::{debug, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{ParseError as URLParseError, Url};
use viaduct::{Error as ViaductError, Request, Response};

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
    pub backoff: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    pub code: u16,
    pub errno: u16,
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum KintoError {
    #[error("a server error occured on {} {}: {}", response.request_method, response.url, info)]
    ServerError {
        response: Response,
        info: ErrorResponse,
        retry_after: Option<u64>,
    },
    #[error("the server responded with unexpected content on {} {}: HTTP {}", response.request_method, response.url, response.status)]
    UnexpectedResponse { response: Response },
    #[error("invalid request on {} {}: {}", response.request_method, response.url, info)]
    ClientRequestError {
        response: Response,
        info: ErrorResponse,
    },
    #[error("changeset timestamp could not be parsed: {0}")]
    InvalidChangesetTimestamp(String),
    #[error("changeset content could not be parsed: {0}")]
    InvalidChangesetBody(#[from] serde_json::Error),
    #[error("unknown collection: {bucket}/{collection}")]
    UnknownCollection { bucket: String, collection: String },
    #[error("HTTP backend issue: {0}")]
    HTTPBackendError(#[from] ViaductError),
    #[error("bad URL format: {0}")]
    URLError(#[from] URLParseError),
}

type Result<T> = std::result::Result<T, KintoError>;

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HTTP {} {}: {} (#{})",
            self.code, self.error, self.message, self.errno
        )
    }
}

pub fn get_latest_change_timestamp(server: &str, bid: &str, cid: &str) -> Result<u64> {
    // When we fetch the monitor/changes endpoint manually (ie. not from a push notification)
    // we cannot know the current timestamp, and use 0 abritrarily.
    let expected = 0;
    let response = get_changeset(&server, "monitor", "changes", expected, None)?;
    let change = response
        .changes
        .iter()
        .find(|&x| x["bucket"] == bid && x["collection"] == cid)
        .ok_or_else(|| KintoError::UnknownCollection {
            bucket: bid.to_string(),
            collection: cid.to_string(),
        })?;

    let last_modified = change["last_modified"].as_u64().ok_or_else(|| {
        KintoError::InvalidChangesetTimestamp(change["last_modified"].to_string())
    })?;

    debug!("{}/{}: last_modified={}", bid, cid, last_modified);

    Ok(last_modified)
}

/// Fetches the collection content from the server.
pub fn get_changeset(
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
    since: Option<u64>,
) -> Result<ChangesetResponse> {
    let since_param = since.map_or_else(String::new, |v| format!("&_since={}", v));
    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}{}",
        server, bid, cid, expected, since_param
    );
    info!("Fetch {}...", url);
    let response = Request::get(Url::parse(&url)?).send()?;

    if !response.is_success() {
        // Try to parse the server error response into JSON.
        // See https://docs.kinto-storage.org/en/stable/api/1.x/errors.html#error-responses
        let info: ErrorResponse = match response.json() {
            Ok(v) => v,
            Err(_) => return Err(KintoError::UnexpectedResponse { response }),
        };

        // Error due to the client. The request must be modified.
        if response.is_client_error() {
            return Err(KintoError::ClientRequestError { response, info });
        }

        if response.is_server_error() {
            let retry_after = response
                .headers
                .get("retry-after")
                .map_or_else(|| None, |v| v.parse::<u64>().ok());

            return Err(KintoError::ServerError {
                response,
                info,
                retry_after,
            });
        }
    }

    let size: i64 = response
        .headers
        .get("content-length")
        .map_or_else(|| -1, |v| v.parse().unwrap_or(-1));

    debug!("Download {:?} bytes...", size);
    let mut changeset: ChangesetResponse = response.json()?;

    // Check if server is indicating to clients to back-off.
    changeset.backoff = response.headers.get("backoff").and_then(|v| v.parse().ok());

    Ok(changeset)
}

#[cfg(test)]
mod tests {
    use super::{get_changeset, get_latest_change_timestamp, KintoError};
    use httpmock::MockServer;
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

        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
                r#"{
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
                }"#,
            );
        });

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
        assert_eq!(
            err.to_string(),
            "bad URL format: relative URL without a base"
        )
    }

    #[test]
    fn test_bad_json() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");

        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
                r#"{
                    "met :
                }"#,
            );
        });

        let err =
            get_latest_change_timestamp(&mock_server_address, "main", "url-classifier-skip-urls")
                .unwrap_err();
        assert_eq!(err.to_string(), "changeset content could not be parsed: control character (\\u0000-\\u001F) found while parsing a string at line 3 column 0");

        get_latest_change_mock.delete();
    }

    #[test]
    fn test_bad_timestamp() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");

        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
                r#"{
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
                }"#,
            );
        });

        let err =
            get_latest_change_timestamp(&mock_server_address, "main", "url-classifier-skip-urls")
                .unwrap_err();

        match err {
            KintoError::InvalidChangesetTimestamp(_) => {
                assert_eq!(
                    err.to_string(),
                    "changeset timestamp could not be parsed: \"foo\""
                )
            }
            e => assert!(false, "Unexpected error type: {:?}", e),
        };

        get_latest_change_mock.delete();
    }

    #[test]
    fn test_client_error_response() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/cfr/changeset")
                .query_param("_expected", "451");
            then.status(400).body(
                r#"{
                    "code": 400,
                    "error": "Bad request",
                    "errno": 123,
                    "message": "Bad value '0' for '_expected'",
                    "details": {
                        "field": "_expected",
                        "location": "querystring"
                    }
                }"#,
            );
        });

        let err = get_changeset(&mock_server_address, "main", "cfr", 451, None).unwrap_err();

        match err {
            KintoError::ClientRequestError { ref info, .. } => {
                assert_eq!(err.to_string(), format!("invalid request on GET {}/buckets/main/collections/cfr/changeset?_expected=451: HTTP 400 Bad request: Bad value \'0\' for \'_expected\' (#123)", mock_server.base_url()));
                assert_eq!(info.errno, 123);
                assert_eq!(info.code, 400);
                assert_eq!(info.error, "Bad request");
                let details = info.details.as_ref().unwrap();
                assert_eq!(details["field"].as_str().unwrap(), "_expected");
            }
            e => assert!(false, "Unexpected error type: {:?}", e),
        };

        get_changeset_mock.delete();
    }

    #[test]
    fn test_server_error_response() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/cfr/changeset")
                .query_param("_expected", "42");
            then.status(503).header("Retry-After", "360").body(
                r#"{
                    "code": 503,
                    "error": "Service unavailable",
                    "errno": 999,
                    "message": "Boom"
                }"#,
            );
        });

        let err = get_changeset(&mock_server_address, "main", "cfr", 42, None).unwrap_err();

        match err {
            KintoError::ServerError {
                retry_after,
                ref info,
                ..
            } => {
                assert_eq!(err.to_string(), format!("a server error occured on GET {}/buckets/main/collections/cfr/changeset?_expected=42: HTTP 503 Service unavailable: Boom (#999)", mock_server.base_url()));
                assert_eq!(retry_after, Some(360));
                assert_eq!(info.errno, 999);
                assert_eq!(info.code, 503);
                assert_eq!(info.error, "Service unavailable");
                assert_eq!(info.details, None);
            }
            e => assert!(false, "Unexpected error type: {:?}", e),
        };

        get_changeset_mock.delete();
    }

    #[test]
    fn test_fetch_follows_redirects() {
        init();

        let mock_server = MockServer::start();

        let mut redirects_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.status(302)
                .header("Location", "/v2/buckets/monitor/collections/changes/changeset");
        });

        let mut changeset_mock = mock_server.mock(|when, then| {
            when.path("/v2/buckets/monitor/collections/changes/changeset");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [
                        {
                            "id": "1234",
                            "last_modified": 5678,
                            "bucket":"main",
                            "collection":"crlite"
                        }
                    ],
                    "timestamp": 42
                }"#,
            );
        });

        let res =
            get_latest_change_timestamp(&mock_server.url(""), "main", "crlite")
                .unwrap();

        assert_eq!(res, 5678);

        redirects_mock.assert();
        changeset_mock.assert();

        redirects_mock.delete();
        changeset_mock.delete();
    }
}
