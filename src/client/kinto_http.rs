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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ErrorResponse {
    pub code: u16,
    pub errno: u16,
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, PartialEq)]
pub enum KintoError {
    /// Errors related to a malformed request.
    ClientError {
        name: String,
        response: Option<ErrorResponse>,
    },
    /// Errors occured on the server side.
    ServerError {
        name: String,
        retry_after: Option<u64>,
        response: Option<ErrorResponse>,
    },
    ContentError {
        name: String,
    },
    UnknownCollection {
        bucket: String,
        collection: String,
    },
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HTTP {} {}: {} (#{})",
            self.code, self.error, self.message, self.errno
        )
    }
}

impl From<ViaductError> for KintoError {
    fn from(err: ViaductError) -> Self {
        KintoError::ClientError {
            name: format!("Viaduct error: {}", err),
            response: None,
        }
    }
}

impl From<ParseError> for KintoError {
    fn from(err: ParseError) -> Self {
        KintoError::ClientError {
            name: format!("URL parse error: {}", err),
            response: None,
        }
    }
}

pub fn get_latest_change_timestamp(server: &str, bid: &str, cid: &str) -> Result<u64, KintoError> {
    // When we fetch the monitor/changes endpoint manually (ie. not from a push notification)
    // we cannot know the current timestamp, and use 0 abritrarily.
    let expected = 0;
    let response = get_changeset(&server, "monitor", "changes", expected, None)?;
    let change = response
        .changes
        .iter()
        .find(|&x| x["bucket"] == bid && x["collection"] == cid)
        .ok_or(KintoError::UnknownCollection {
            bucket: bid.to_string(),
            collection: cid.to_string(),
        })?;

    let last_modified = change["last_modified"]
        .as_u64()
        .ok_or(KintoError::ContentError {
            name: format!("Bad server timestamp: {}", change["last_modified"]),
        })?;

    debug!("{}/{}: last_modified={}", bid, cid, last_modified);

    Ok(last_modified)
}

pub fn get_changeset(
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
    since: Option<u64>,
) -> Result<ChangesetResponse, KintoError> {
    let since_param = since.map_or_else(String::new, |v| format!("&_since={}", v));
    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}{}",
        server, bid, cid, expected, since_param
    );
    info!("Fetch {}...", url);
    let resp = Request::get(Url::parse(&url)?).send()?;

    if !resp.is_success() {
        let error: ErrorResponse = resp.json().unwrap_or(ErrorResponse {
            code: resp.status,
            errno: 999,
            error: "Unknown".to_owned(),
            message: "Bad error format".to_owned(),
            details: None,
        });

        if resp.is_client_error() {
            return Err(KintoError::ClientError {
                name: format!("{} for {}", error, resp.url.path()),
                response: Some(error),
            });
        }

        if resp.is_server_error() {
            let retry_after = resp
                .headers
                .get("retry-after")
                .map_or_else(|| None, |v| v.parse::<u64>().ok());

            return Err(KintoError::ServerError {
                name: format!("{} from {}", error, resp.url.path()),
                retry_after,
                response: Some(error),
            });
        }
    }

    let size: i64 = resp
        .headers
        .get("content-length")
        .map_or_else(|| -1, |v| v.parse().unwrap_or(-1));

    debug!("Download {:?} bytes...", size);
    resp.json().map_err(|err| KintoError::ContentError {
        name: format!("JSON content error: {}", err),
    })
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
                }"#
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
        match err {
            KintoError::ClientError { name, .. } => {
                assert_eq!(name, "URL parse error: relative URL without a base")
            }
            e => assert!(false, format!("Unexpected error type: {:?}", e)),
        };
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
                }"#
            );
        });

        let err =
            get_latest_change_timestamp(&mock_server_address, "main", "url-classifier-skip-urls")
                .unwrap_err();

        match err {
            KintoError::ContentError { name, .. } => {
                assert!(name.contains("JSON content error: control character"))
            }
            e => assert!(false, format!("Unexpected error type: {:?}", e)),
        };

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
            KintoError::ContentError { name, .. } => {
                assert_eq!(name, "Bad server timestamp: \"foo\"")
            }
            e => assert!(false, format!("Unexpected error type: {:?}", e)),
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
                    "message": "Bad value '0' for _expected",
                    "details": {
                        "field": "_expected",
                        "location": "querystring"
                    }
                }"#,
            );
        });

        let err = get_changeset(&mock_server_address, "main", "cfr", 451, None).unwrap_err();

        match err {
            KintoError::ClientError { name, response } => {
                assert_eq!(name, "HTTP 400 Bad request: Bad value '0' for _expected (#123) for /buckets/main/collections/cfr/changeset".to_owned());
                let info = &response.unwrap();
                let details = info.details.as_ref().unwrap();
                assert_eq!(info.errno, 123);
                assert_eq!(info.code, 400);
                assert_eq!(info.error, "Bad request");
                assert_eq!(details["field"].as_str().unwrap(), "_expected");
            }
            e => assert!(false, format!("Unexpected error type: {:?}", e)),
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
                name,
                retry_after,
                response,
            } => {
                assert_eq!(name, "HTTP 503 Service unavailable: Boom (#999) from /buckets/main/collections/cfr/changeset".to_owned());
                assert_eq!(retry_after, Some(360));
                let info = &response.unwrap();
                assert_eq!(info.errno, 999);
                assert_eq!(info.code, 503);
                assert_eq!(info.error, "Service unavailable");
                assert_eq!(info.details, None);
            }
            e => assert!(false, format!("Unexpected error type: {:?}", e)),
        };

        get_changeset_mock.delete();
    }
}
