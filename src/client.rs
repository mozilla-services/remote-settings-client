/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;
mod storage;

use serde::Serialize;

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject};
pub use signatures::{SignatureError, Verification};
pub use storage::{RemoteStorage, RemoteStorageError};

#[cfg(feature = "ring_verifier")]
use crate::client::signatures::ring_verifier::RingVerifier as DefaultVerifier;

#[cfg(not(feature = "ring_verifier"))]
use crate::client::signatures::default_verifier::DefaultVerifier;

use crate::client::storage::default_cache::DefaultCache as DefaultCache;

pub const DEFAULT_SERVER_URL: &str = "https://firefox.settings.services.mozilla.com/v1";
pub const DEFAULT_BUCKET_NAME: &str = "main";

#[derive(Debug, PartialEq)]
pub enum ClientError {
    VerificationError { name: String },
    Error { name: String },
}

impl From<KintoError> for ClientError {
    fn from(err: KintoError) -> Self {
        match err {
            KintoError::ServerError { name } => ClientError::Error { name },
            KintoError::ClientError { name } => ClientError::Error { name },
        }
    }
}

impl From<RemoteStorageError> for ClientError {
    fn from(err: RemoteStorageError) -> Self {
        err.into()
    }
}

impl From<serde_json::error::Error> for ClientError {
    fn from(err: serde_json::error::Error) -> Self {
        err.into()
    }
}

impl From<std::string::FromUtf8Error> for ClientError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        err.into()
    }
}

impl From<SignatureError> for ClientError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::CertificateError { name } => ClientError::VerificationError { name },
            SignatureError::VerificationError { name } => ClientError::VerificationError { name },
            SignatureError::InvalidSignature { name } => ClientError::VerificationError { name },
        }
    }
}

/// Response body from remote-settings server
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<KintoObject>,
    pub timestamp: u64,
}

impl From<Collection> for Vec<u8> {
    fn from(collection: Collection) -> Self {
        match serde_json::to_string(&collection) {
            Ok(val) => return val.into_bytes(),
            Err(_err) => {
                return "".into()
            },
        }
    }
}

pub struct ClientBuilder {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    verifier: Box<dyn Verification>,
    cache: Box<dyn RemoteStorage>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Constructs a new `ClientBuilder`.
    ///
    /// This is the same as `Client::builder()`.
    pub fn new() -> ClientBuilder {
        ClientBuilder {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(DefaultVerifier {}),
            cache: Box::new(DefaultCache {}),
        }
    }

    /// Add custom server url to Client
    pub fn server_url(mut self, server_url: &str) -> ClientBuilder {
        self.server_url = server_url.to_owned();
        self
    }

    /// Add custom bucket name to Client
    pub fn bucket_name(mut self, bucket_name: &str) -> ClientBuilder {
        self.bucket_name = bucket_name.to_owned();
        self
    }

    /// Add custom collection name to Client
    pub fn collection_name(mut self, collection_name: &str) -> ClientBuilder {
        self.collection_name = collection_name.to_owned();
        self
    }

    /// Add custom signature verifier to Client
    pub fn verifier(mut self, verifier: Box<dyn Verification>) -> ClientBuilder {
        self.verifier = verifier;
        self
    }

    /// Add custom cache storage implementation to Client
    pub fn cache(mut self, cache: Box<dyn RemoteStorage>) -> ClientBuilder {
        self.cache = cache;
        self
    }

    /// Build Client from ClientBuilder
    pub fn build(self) -> Client {
        Client {
            server_url: self.server_url,
            bucket_name: self.bucket_name,
            collection_name: self.collection_name,
            verifier: self.verifier,
            cache: self.cache,
        }
    }
}

/// Handles requests to Remote-Settings
/// # Examples
/// Create Client with collection_name and without custom Verifier
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::{Client, Collection};
/// # fn main() {
///   let client = Client::builder().collection_name("collection_name").build();
/// # }
/// ```
///
/// Create Client with custom Verifier
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::{Client, Collection};
/// struct CustomVerifier{}
///
/// impl Verification for CustomVerifier {
///    fn verify(&mut self, collection: &Collection) -> Result<(), SignatureError> {
///        Ok(()) // everything is verified!
///    }
/// }
///
/// # fn main() {
///   let client = Client::builder().collection_name("collection_name").verifier(Box::new(CustomVerifier{})).build();
/// # }
/// ```
pub struct Client {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    verifier: Box<dyn Verification>,
    cache: Box<dyn RemoteStorage>,
}

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    ///
    /// This is the same as `ClientBuilder::new()`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    fn fetch_records_and_verify(&mut self, remote_timestamp: u64) -> Result<Collection, ClientError> {

        let changeset_response = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            remote_timestamp,
        )?;

        debug!("changeset.metadata {}", serde_json::to_string_pretty(&changeset_response.metadata)?);

        let collection: Collection = self.create_collection_from_response(changeset_response);
        self.verifier.verify(&collection)?;

        Ok(collection)
    }

    fn get_latest_collection_timestamp(&mut self) -> Result<u64, ClientError> {
        let expected = get_latest_change_timestamp(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
        )?;

        Ok(expected)
    }

    fn create_collection_from_response(&mut self, change_set_response: ChangesetResponse) -> Collection {
        return Collection {
            bid: self.bucket_name.to_owned(),
            cid: self.collection_name.to_owned(),
            metadata: change_set_response.metadata,
            records: change_set_response.changes,
            timestamp: change_set_response.timestamp
        };
    }

    /// Fetches records for a given collection from the remote-settings server
    ///
    /// # Examples
    /// ```text
    /// fn main() {
    ///   match Client::builder().collection_name("collection").build().get() {
    ///     Ok(records) => println!("{:?}", records),
    ///     Err(error) => println!("Error fetching/verifying records: {:?}", error)
    ///   };
    /// }
    /// ```
    ///
    /// # Errors
    /// If an error occurs while fetching records, ```ClientError``` is returned
    pub fn get(&mut self) -> Result<Vec<KintoObject>, ClientError> {

        // If storage is empty for this bucket/collection, fetch from .../changeset, validate signature, store locally, and return records
        // Otherwise, obtain current remote timestamp of collection from server (done in #26)
        // If remote timestamp is different than local, fetch, validate signature, overwrite local existing data and return records
        // If remote timestamp is same as local, validate signature and return records. If validating signature fails, fetch, validate, overwrite, and return records.

        let remote_timestamp = self.get_latest_collection_timestamp()?;
        let key = format!("{}-{}:records", self.bucket_name, self.collection_name).as_bytes().to_vec();
        debug!("get key={:?}", String::from_utf8(key.clone()).unwrap());

        match self.cache.retrieve(key.clone()) {
            Ok(val) => {

                let value = val.unwrap_or_else(|| Vec::new());

                if value.len() == 0 {
                    return Err(RemoteStorageError::Error { name: "read error - key not found".to_owned() }.into());
                }

                let value_str = String::from_utf8(value.to_vec())?;
                // convert JSON object to ChangesetResponse object
                let cached_change_response: ChangesetResponse = serde_json::from_str(&value_str)?;

                debug!("The remote timestamp is {} and local timestamp is {}", remote_timestamp, cached_change_response.timestamp);
                if remote_timestamp != cached_change_response.timestamp {
                    // fetch records, validate signature, overwrite local existing data and return records
                    let collection = self.fetch_records_and_verify(remote_timestamp)?;

                    let collection_bytes: Vec<u8> = collection.clone().into();
                    let key: Vec<u8> = format!("{}-{}:records", collection.bid, collection.cid).as_bytes().to_vec();

                    // before returning records, we want to override it into the cache
                    self.cache.store(key, collection_bytes)?;

                    return Ok(collection.records)
                }

                // otherwise just validate signature and return records but if valdiation fails, then fetch, validate, overwrite and return records
                let collection = self.create_collection_from_response(cached_change_response);
                let records = match self.verifier.verify(&collection) {
                    Ok(()) => collection.records,
                    Err(_err) => {
                        let collection = self.fetch_records_and_verify(remote_timestamp)?;
                        collection.records
                    },
                };

                return Ok(records)
            },
            Err(err) => {
                debug!("error - {:?} : accessing key={:?} from cache - fetching records from server", err, key);

                let collection = self.fetch_records_and_verify(remote_timestamp)?;
                return Ok(collection.records)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::signatures::{SignatureError, Verification};
    use super::{Client, ClientError, Collection, RemoteStorage, RemoteStorageError};
    use env_logger;
    use serde_json::json;
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;
    use std::collections::HashMap as HashMap;
    use std::fs::remove_file;
    use log::{error};

    struct MockVerifier {
        verify_result: Vec<Result<(), SignatureError>>
    }

    pub struct MockCache {
        map: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl RemoteStorage for MockCache {

        fn store(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RemoteStorageError> {
            let file_name = format!("{}.bin", String::from_utf8(key)?).as_bytes().to_vec();
            self.map.insert(file_name, value);
            Ok(())
        }

        fn retrieve(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, RemoteStorageError> {
            let file_name = format!("{}.bin", String::from_utf8(key)?).as_bytes().to_vec();

            match self.map.get(&file_name) {
                Some(val) => Ok(Some((*val).to_owned())),
                None => Err(RemoteStorageError::ReadError { name: "key does not exist".to_owned() })
            }
        }
    }

    impl Verification for MockVerifier {
        fn verify(&mut self, _collection: &Collection) -> Result<(), SignatureError> {
            let result: Result<(), SignatureError> = self.verify_result.remove(0);

            return result
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _ = set_backend(&ReqwestBackend);
    }

    fn cleanup(file_path: &str) {
        match remove_file(&file_path) {
            Ok(()) => {},
            Err(err) => error!("error removing file - {} : {}", file_path, err)
        }
    }

    fn make_cache(key: &str, value: &str) -> Box<MockCache> {

        let key_bytes = key.as_bytes().to_vec();
        let val_bytes = value.as_bytes().to_vec();

        let mut cache = MockCache {map: HashMap::new()};

        cache.store(key_bytes, val_bytes).unwrap();

        Box::new(cache)
    }

    fn test_get(
        mock_server: &MockServer,
        mut client: Client,
        latest_change_response: &str,
        records_response: &str,
        fetch_remote: bool,
        expected_result: Result<Vec<serde_json::Value>, ClientError>,
    ) {
        let mut get_latest_change_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/monitor/collections/changes/changeset")
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(latest_change_response)
            .create_on(&mock_server);

        let mut get_changeset_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/main/collections/url-classifier-skip-urls/changeset")
            .expect_query_param("_expected", "9173")
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(records_response)
            .create_on(&mock_server);

        if !fetch_remote {
            get_changeset_mock.delete();
        }

        let actual_result = client.get();
        assert_eq!(1, get_latest_change_mock.times_called());
        assert_eq!(actual_result, expected_result);

        get_latest_change_mock.delete();

        if fetch_remote {
            get_changeset_mock.delete();
        }

        cleanup(&format!("{}-{}:records.bin", client.bucket_name, client.collection_name));
    }

    #[test]
    fn test_unknown_collection() {
        init();

        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("");

        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(VerifierWithNoError {}))
                .build(),
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#,
            r#"{
                "metadata": {
                    "data": "test"
                },
                "changes": [],
                "timestamp": 0
            }"#,
            Err(ClientError::Error {
                name: format!(
                    "Unknown collection {}/{}",
                    "main", "url-classifier-skip-urls"
                ),
            }),
        );
    }

    #[test]
    fn test_get_verification() {
        init();

        let mock_server = MockServer::start();

        let mock_server_address = mock_server.url("");

        const STALE_TIMESTAMP_PAYLOAD: &str = r#"{
            "metadata": {
                "data": "test"
            },
            "changes": [{
                "id": 1,
                "last_modified": 100
            }],
            "timestamp": 0
        }"#;

        const LATEST_TIMESTAMP_PAYLOAD: &str = r#"{
            "metadata": {
                "data": "test"
            },
            "changes": [{
                "id": 1,
                "last_modified": 100
            }],
            "timestamp": 9173
        }"#;

        let valid_latest_change_response = &format!(
            "{}",
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
                "timestamp": 0
            }"#
        );

        // custom verifier with verification error (no local record present)
        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(MockVerifier {verify_result: vec![Err(SignatureError::VerificationError { name: "signature verification error".to_owned() })]}))
                .build(),
            valid_latest_change_response,
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#,
            true,
            Err(ClientError::VerificationError {
                name: "signature verification error".to_owned(),
            }),
        );

        // custom verifier with no error (no local record present)
        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(MockVerifier {
                    verify_result: vec![Ok(())]
                }))
                .build(),
            valid_latest_change_response,
            r#"{
                "metadata": {
                    "data": "test"
                },
                "changes": [{
                    "id": 1,
                    "last_modified": 100
                }],
                "timestamp": 0
            }"#,
            true,
            Ok(vec![json!({
                "id": 1,
                "last_modified": 100
            })]),
        );

        // custom verifier with invalid signature error (no local record present)
        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(MockVerifier { verify_result: vec![Err(SignatureError::InvalidSignature { name: "invalid signature error".to_owned() })] }))
                .build(),
            valid_latest_change_response,
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#,
            true,
            Err(ClientError::VerificationError {
                name: "invalid signature error".to_owned(),
            }),
        );

        test_get(&mock_server,Client::builder()
            .server_url(&mock_server_address)
            .collection_name("url-classifier-skip-urls")
            .verifier(Box::new(VerifierWithNoError {}))
            .build(), &format!(
            "{}",
            r#"{
            "data": []
        }"#
        ), r#"{
            "metadata": {
                "data": "test"
            },
            "changes": [],
            "timestamp": 0
        }"#, Err(ClientError::Error { name: format!("Unknown collection {}/{}", "main", "url-classifier-skip-urls") }));
    }
}
