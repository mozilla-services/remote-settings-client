/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::client::{net::Headers, net::Method, net::Requester, net::Response};
use std::collections::HashMap;

use log::{debug, info};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{ParseError as URLParseError, Url};

pub type KintoObject = serde_json::Value;

#[derive(Deserialize, Debug)]
struct KintoResponse<T> {
    data: T,
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
    #[error("a server error occured on {:?} {}: {}", method, url, info)]
    ServerError {
        method: Method,
        url: String,
        response: Response,
        info: ErrorResponse,
        retry_after: Option<u64>,
    },
    #[error("the server responded with unexpected content on GET {}: HTTP {}", url, response.status)]
    UnexpectedResponse { url: String, response: Response },
    #[error("invalid request on GET {}: {}", url, info)]
    ClientRequestError {
        url: String,
        response: Response,
        info: ErrorResponse,
    },
    #[error("changeset timestamp could not be parsed: {0}")]
    InvalidChangesetTimestamp(String),
    #[error("changeset content could not be parsed: {0}")]
    InvalidChangesetBody(#[from] serde_json::Error),
    #[error("unknown collection: {bucket}/{collection}")]
    UnknownCollection { bucket: String, collection: String },
    #[error("HTTP backend issue")]
    HTTPBackendError(),
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

pub fn get_latest_change_timestamp(
    requester: &Box<dyn Requester + 'static>,
    server: &str,
    bid: &str,
    cid: &str,
) -> Result<u64> {
    // When we fetch the monitor/changes endpoint manually (ie. not from a push notification)
    // we cannot know the current timestamp, and use 0 arbitrarily.
    let expected = 0;
    let response = get_changeset(requester, server, "monitor", "changes", expected, None)?;
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
    requester: &Box<dyn Requester + 'static>,
    server: &str,
    bid: &str,
    cid: &str,
    expected: u64,
    since: Option<u64>,
) -> Result<ChangesetResponse> {
    let since_param = since.map_or_else(String::new, |v| format!(r#"&_since="{}""#, v));
    let url = format!(
        "{}/buckets/{}/collections/{}/changeset?_expected={}{}",
        server, bid, cid, expected, since_param
    );
    let response = _request_resource(requester.as_ref(), None, Method::GET, url, vec![])?;
    let mut changeset: ChangesetResponse = serde_json::from_slice(&response.body)?;

    // Check if server is indicating to clients to back-off.
    changeset.backoff = response.headers.get("backoff").and_then(|v| v.parse().ok());

    Ok(changeset)
}

pub fn put_record<T>(
    requester: &'_ (dyn Requester + 'static),
    server: &str,
    authorization: Option<String>,
    bid: &str,
    cid: &str,
    rid: &str,
    data: &KintoObject,
) -> Result<T>
where
    T: From<KintoObject>,
{
    let record_url = format!(
        "{}/collections/{}/records/{}",
        _workspace_url(server, bid),
        cid,
        rid,
    );

    let mut json_body = HashMap::new();
    json_body.insert("data", data);
    let json_bytes: Vec<u8> = serde_json::to_string(&json_body)?.into();

    let response = _request_resource(
        requester,
        authorization,
        Method::PUT,
        record_url,
        json_bytes,
    )?;
    let kr: KintoResponse<KintoObject> = serde_json::from_slice(&response.body)?;
    Ok(kr.data.into())
}

pub fn delete_record<T>(
    requester: &'_ (dyn Requester + 'static),
    server: &str,
    authorization: Option<String>,
    bid: &str,
    cid: &str,
    rid: &str,
) -> Result<T>
where
    T: From<KintoObject>,
{
    let record_url = format!(
        "{}/collections/{}/records/{}",
        _workspace_url(server, bid),
        cid,
        rid,
    );
    let response = _request_resource(requester, authorization, Method::DELETE, record_url, vec![])?;
    let kr: KintoResponse<KintoObject> = serde_json::from_slice(&response.body)?;
    Ok(kr.data.into())
}

pub fn patch_collection<T>(
    requester: &'_ (dyn Requester + 'static),
    server: &str,
    authorization: Option<String>,
    bid: &str,
    cid: &str,
    data: &KintoObject,
) -> Result<T>
where
    T: From<KintoObject>,
{
    let collection_url = format!("{}/collections/{}", _workspace_url(server, bid), cid);

    let mut json_body = HashMap::new();
    json_body.insert("data", data);
    let json_bytes: Vec<u8> = serde_json::to_string(&json_body)?.into();

    let response = _request_resource(
        requester,
        authorization,
        Method::PATCH,
        collection_url,
        json_bytes,
    )?;
    let kr: KintoResponse<KintoObject> = serde_json::from_slice(&response.body)?;
    Ok(kr.data.into())
}

fn _workspace_url(server: &str, bid: &str) -> String {
    // This client will use the workspace bucket for the
    // write operations.
    format!(
        "{}/buckets/{}",
        server,
        match bid
            .replace("-preview", "")
            .replace("-workspace", "")
            .as_str()
        {
            "blocklists" => "staging".into(),
            "preview" => "staging".into(),
            "security-state" => "security-state-staging".into(),
            b => format!("{}-workspace", b),
        }
    )
}

fn _request_resource(
    requester: &'_ (dyn Requester + 'static),
    authorization: Option<String>,
    method: Method,
    url: String,
    data: Vec<u8>,
) -> Result<Response> {
    let mut headers = Headers::new();
    // Add a specific User-Agent
    headers.insert(
        "User-Agent".into(),
        format!("remote_settings/{}", env!("CARGO_PKG_VERSION")),
    );
    // Add Authorization (for write methods)
    if let Some(auth) = authorization {
        headers.insert("Authorization".into(), auth);
    }

    info!("{:?} {}...", method, url);
    let response = requester
        .request_json(method, Url::parse(&url)?, data, headers)
        .map_err(|_err| KintoError::HTTPBackendError())?;

    if !response.is_success() {
        // Try to parse the server error response into JSON.
        // See https://docs.kinto-storage.org/en/stable/api/1.x/errors.html#error-responses
        let info: ErrorResponse = match serde_json::from_slice(&response.body) {
            Ok(v) => v,
            Err(_) => return Err(KintoError::UnexpectedResponse { url, response }),
        };

        // Error due to the client. The request must be modified.
        if response.is_client_error() {
            return Err(KintoError::ClientRequestError {
                url,
                response,
                info,
            });
        }

        if response.is_server_error() {
            let retry_after = response
                .headers
                .get("retry-after")
                .map_or_else(|| None, |v| v.parse::<u64>().ok());

            return Err(KintoError::ServerError {
                method,
                url,
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
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{
        delete_record, get_changeset, get_latest_change_timestamp, patch_collection, put_record,
        KintoError, KintoObject,
    };
    use crate::client::net::{Headers, Method, Requester, TestHttpClient, TestResponse};
    use httpmock::MockServer;
    use serde_json::json;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_fetch() {
        init();

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(vec![TestResponse {
                request_method: Method::GET,
                request_url:
                    "https://example.com/v1/buckets/monitor/collections/changes/changeset?_expected=0"
                        .to_string(),
                response_status: 200,
                response_body: r#"{
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
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            }]));

        let res = get_latest_change_timestamp(
            &test_client,
            "https://example.com/v1",
            "main",
            "url-classifier-skip-urls",
        )
        .unwrap();

        assert_eq!(res, 9173);
    }

    #[test]
    fn test_bad_url() {
        init();

        let _ = viaduct::set_backend(&viaduct_reqwest::ReqwestBackend);
        let viaduct_client: Box<dyn Requester + 'static> =
            Box::new(crate::client::net::ViaductClient);

        let err =
            get_latest_change_timestamp(&viaduct_client, "%^", "main", "url-classifier-skip-urls")
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "bad URL format: relative URL without a base"
        )
    }

    #[test]
    fn test_bad_json() {
        init();

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(vec![TestResponse {
                request_method: Method::GET,
                request_url:
                    "https://example.com/buckets/monitor/collections/changes/changeset?_expected=0"
                        .to_string(),
                response_status: 200,
                response_body: r#"{
                    "met :
                }"#
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            }]));

        let err = get_latest_change_timestamp(
            &test_client,
            "https://example.com",
            "main",
            "url-classifier-skip-urls",
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "changeset content could not be parsed: control character (\\u0000-\\u001F) found while parsing a string at line 3 column 0");
    }

    #[test]
    fn test_bad_timestamp() {
        init();

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(vec![TestResponse {
                request_method: Method::GET,
                request_url:
                    "https://example.com/v1/buckets/monitor/collections/changes/changeset?_expected=0"
                        .to_string(),
                response_status: 200,
                response_body: r#"{
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
                }"#
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            }]));

        let err = get_latest_change_timestamp(
            &test_client,
            "https://example.com/v1",
            "main",
            "url-classifier-skip-urls",
        )
        .unwrap_err();

        match err {
            KintoError::InvalidChangesetTimestamp(_) => {
                assert_eq!(
                    err.to_string(),
                    "changeset timestamp could not be parsed: \"foo\""
                )
            }
            e => panic!("Unexpected error type: {:?}", e),
        };
    }

    #[test]
    fn test_client_error_response() {
        init();

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(vec![TestResponse {
                request_method: Method::GET,
                request_url:
                    "https://example.com/v1/buckets/main/collections/cfr/changeset?_expected=451"
                        .to_string(),
                response_status: 400,
                response_body: r#"{
                    "code": 400,
                    "error": "Bad request",
                    "errno": 123,
                    "message": "Bad value '0' for '_expected'",
                    "details": {
                        "field": "_expected",
                        "location": "querystring"
                    }
                }"#
                .as_bytes()
                .to_vec(),
                response_headers: Headers::new(),
            }]));

        let err = get_changeset(
            &test_client,
            "https://example.com/v1",
            "main",
            "cfr",
            451,
            None,
        )
        .unwrap_err();

        match err {
            KintoError::ClientRequestError { ref info, .. } => {
                assert_eq!(err.to_string(), "invalid request on GET https://example.com/v1/buckets/main/collections/cfr/changeset?_expected=451: HTTP 400 Bad request: Bad value \'0\' for \'_expected\' (#123)");
                assert_eq!(info.errno, 123);
                assert_eq!(info.code, 400);
                assert_eq!(info.error, "Bad request");
                let details = info.details.as_ref().unwrap();
                assert_eq!(details["field"].as_str().unwrap(), "_expected");
            }
            e => panic!("Unexpected error type: {:?}", e),
        };
    }

    #[test]
    fn test_server_error_response() {
        init();

        let mut response_headers = Headers::new();
        response_headers.insert("retry-after".to_string(), "360".to_string());

        let test_client: Box<dyn Requester + 'static> =
            Box::new(TestHttpClient::new(vec![TestResponse {
                request_method: Method::GET,
                request_url:
                    "https://example.com/v1/buckets/main/collections/cfr/changeset?_expected=42"
                        .to_string(),
                response_status: 503,
                response_body: r#"{
                    "code": 503,
                    "error": "Service unavailable",
                    "errno": 999,
                    "message": "Boom"
                }"#
                .as_bytes()
                .to_vec(),
                response_headers,
            }]));

        let err = get_changeset(
            &test_client,
            "https://example.com/v1",
            "main",
            "cfr",
            42,
            None,
        )
        .unwrap_err();

        match err {
            KintoError::ServerError {
                retry_after,
                ref info,
                ..
            } => {
                assert_eq!(err.to_string(), "a server error occured on GET https://example.com/v1/buckets/main/collections/cfr/changeset?_expected=42: HTTP 503 Service unavailable: Boom (#999)");
                assert_eq!(retry_after, Some(360));
                assert_eq!(info.errno, 999);
                assert_eq!(info.code, 503);
                assert_eq!(info.error, "Service unavailable");
                assert_eq!(info.details, None);
            }
            e => panic!("Unexpected error type: {:?}", e),
        };
    }

    #[test]
    fn test_fetch_follows_redirects() {
        init();

        let mock_server = MockServer::start();

        let mut redirects_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.status(302).header(
                "Location",
                "/v2/buckets/monitor/collections/changes/changeset",
            );
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

        let _ = viaduct::set_backend(&viaduct_reqwest::ReqwestBackend);
        let viaduct_client: Box<dyn Requester + 'static> =
            Box::new(crate::client::net::ViaductClient);
        let res =
            get_latest_change_timestamp(&viaduct_client, &mock_server.url(""), "main", "crlite")
                .unwrap();

        assert_eq!(res, 5678);

        redirects_mock.assert();
        changeset_mock.assert();

        redirects_mock.delete();
        changeset_mock.delete();
    }

    #[test]
    fn test_put_record() {
        init();

        let mock_server = MockServer::start();

        let put_record_mock = mock_server.mock(|when, then| {
            when.method("PUT")
                .path("/buckets/main-workspace/collections/cid/records/xyz")
                .body_contains("\"field\":\"value\"")
                .header_exists("Authorization");
            then.status(200).body(
                r#"{
                    "data": {
                        "id": "xyz",
                        "last_modified": 42,
                        "field": "value"
                    }
                }"#,
            );
        });

        let _ = viaduct::set_backend(&viaduct_reqwest::ReqwestBackend);
        let viaduct_client: Box<dyn Requester + 'static> =
            Box::new(crate::client::net::ViaductClient);

        let res: KintoObject = put_record(
            viaduct_client.as_ref(),
            &mock_server.url(""),
            Some("Basic abc".into()),
            "main",
            "cid",
            "xyz",
            &json!({
                "field": "value"
            }),
        )
        .unwrap();

        put_record_mock.assert();

        assert_eq!(res["id"], "xyz");
        assert_eq!(res["last_modified"], 42);
        assert_eq!(res["field"], "value");
    }

    #[test]
    fn test_delete_record() {
        init();

        let mock_server = MockServer::start();

        let delete_record_mock = mock_server.mock(|when, then| {
            when.method("DELETE")
                .path("/buckets/main-workspace/collections/cid/records/xyz")
                .header_exists("Authorization");
            then.status(200).body(
                r#"{
                    "data": {
                        "id": "xyz",
                        "last_modified": 42,
                        "deleted": true
                    }
                }"#,
            );
        });

        let _ = viaduct::set_backend(&viaduct_reqwest::ReqwestBackend);
        let viaduct_client: Box<dyn Requester + 'static> =
            Box::new(crate::client::net::ViaductClient);

        let res: KintoObject = delete_record(
            viaduct_client.as_ref(),
            &mock_server.url(""),
            Some("Basic abc".into()),
            "main",
            "cid",
            "xyz",
        )
        .unwrap();

        delete_record_mock.assert();

        assert_eq!(res["id"], "xyz");
        assert_eq!(res["last_modified"], 42);
        assert_eq!(res["deleted"], true);
    }

    #[test]
    fn test_patch_collection() {
        init();

        let mock_server = MockServer::start();

        let patch_collection_mock = mock_server.mock(|when, then| {
            when.method("PATCH")
                .path("/buckets/main-workspace/collections/cid")
                .body_contains("\"status\":\"to-sign\"")
                .header_exists("Authorization");
            then.status(200).body(
                r#"{
                    "data": {
                        "id": "cid",
                        "last_modified": 42,
                        "status": "signed"
                    }
                }"#,
            );
        });

        let _ = viaduct::set_backend(&viaduct_reqwest::ReqwestBackend);
        let viaduct_client: Box<dyn Requester + 'static> =
            Box::new(crate::client::net::ViaductClient);

        let res: KintoObject = patch_collection(
            viaduct_client.as_ref(),
            &mock_server.url(""),
            Some("Basic abc".into()),
            "main-preview",
            "cid",
            &json!({
                "status": "to-sign"
            }),
        )
        .unwrap();

        patch_collection_mock.assert();

        assert_eq!(res["id"], "cid");
        assert_eq!(res["last_modified"], 42);
        assert_eq!(res["status"], "signed");
    }
}
