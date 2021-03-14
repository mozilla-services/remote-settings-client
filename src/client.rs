/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;
mod storage;

use log::{debug, info};
use serde::{Deserialize, Serialize};

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject};
pub use signatures::{SignatureError, Verification};
pub use storage::{dummy_storage::DummyStorage, file_storage::FileStorage, Storage, StorageError};

#[cfg(feature = "ring_verifier")]
use crate::client::signatures::ring_verifier::RingVerifier as DefaultVerifier;

#[cfg(not(feature = "ring_verifier"))]
use crate::client::signatures::default_verifier::DefaultVerifier;

pub const DEFAULT_SERVER_URL: &str = "https://firefox.settings.services.mozilla.com/v1";
pub const DEFAULT_BUCKET_NAME: &str = "main";

#[derive(Debug, PartialEq)]
pub enum ClientError {
    VerificationError { name: String },
    StorageError { name: String },
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

impl From<serde_json::error::Error> for ClientError {
    fn from(err: serde_json::error::Error) -> Self {
        ClientError::StorageError {
            name: format!("Could not de/serialize data: {}", err.to_string()),
        }
    }
}

impl From<StorageError> for ClientError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::ReadError { name } => ClientError::StorageError { name },
            StorageError::Error { name } => ClientError::StorageError { name },
        }
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

/// Representation of a collection on the server
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<KintoObject>,
    pub timestamp: u64,
}

pub struct ClientBuilder {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    verifier: Box<dyn Verification>,
    storage: Box<dyn Storage>,
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
            storage: Box::new(DummyStorage {}),
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

    /// Add custom storage implementation to Client
    pub fn storage(mut self, storage: Box<dyn Storage>) -> ClientBuilder {
        self.storage = storage;
        self
    }

    /// Build Client from ClientBuilder
    pub fn build(self) -> Client {
        Client {
            server_url: self.server_url,
            bucket_name: self.bucket_name,
            collection_name: self.collection_name,
            verifier: self.verifier,
            storage: self.storage,
        }
    }
}

/// Client to fetch Remote Settings data.
///
/// # Examples
/// Create a `Client` for the `cid` collection on the production server:
/// ```rust
/// # use remote_settings_client::Client;
///
/// # fn main() {
/// let client = Client::builder()
///   .collection_name("cid")
///   .build();
/// # }
/// ```
/// Or for a specific server or bucket:
/// ```rust
/// # use remote_settings_client::Client;
///
/// # fn main() {
/// let client = Client::builder()
///   .server_url("https://settings.stage.mozaws.net/v1")
///   .bucket_name("main-preview")
///   .collection_name("cid")
///   .build();
/// # }
/// ```
///
/// ## Signature verification
///
/// When no verifier is explicit specified, the default is chosen based on the enabled crate features:
///
/// | Features        | Description                                |
/// |-----------------|--------------------------------------------|
/// | `[]`            | No signature verification of data          |
/// | `ring_verifier` | Uses the `ring` crate to verify signatures |
///
/// See [`Verification`] for implementing a custom signature verifier.
pub struct Client {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    // Box<dyn Trait> is necessary since implementation of [`Verification`] can be of any size unknown at compile time
    verifier: Box<dyn Verification>,
    storage: Box<dyn Storage>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(DefaultVerifier {}),
            storage: Box::new(DummyStorage {}),
        }
    }
}

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    fn _fetch_records_and_verify(
        &mut self,
        remote_timestamp: u64,
    ) -> Result<Collection, ClientError> {
        let changeset_response = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            Some(remote_timestamp),
        )?;

        let collection = Collection {
            bid: self.bucket_name.to_owned(),
            cid: self.collection_name.to_owned(),
            metadata: changeset_response.metadata,
            records: changeset_response.changes,
            timestamp: changeset_response.timestamp,
        };

        self.verifier.verify(&collection)?;

        Ok(collection)
    }

    /// Fetches records from the server for a given collection
    ///
    /// # Examples
    /// ```rust
    /// # use remote_settings_client::Client;
    /// # use viaduct::set_backend;
    /// # pub use viaduct_reqwest::ReqwestBackend;
    /// # fn main() {
    /// # set_backend(&ReqwestBackend).unwrap();
    /// # let mut client = Client::builder().collection_name("url-classifier-skip-urls").build();
    /// match client.get() {
    ///   Ok(records) => println!("{:?}", records),
    ///   Err(error) => println!("Error fetching/verifying records: {:?}", error)
    /// };
    /// # }
    /// ```
    ///
    /// # Behaviour
    /// Records are cached.
    /// * If stored data is up-to-date and its signature valid, then return records;
    /// * Otherwise fetch from server, verify signature, store result, and return records;
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn get(&mut self) -> Result<Vec<KintoObject>, ClientError> {
        let storage_key = format!("{}/{}:collection", self.bucket_name, self.collection_name);
        debug!("Retrieve from storage with key={:?}", storage_key);
        let stored_bytes: Vec<u8> = self
            .storage
            .retrieve(&storage_key)
            .unwrap_or(None)
            .unwrap_or_else(Vec::new);

        let stored: Option<Collection> = serde_json::from_slice(&stored_bytes).unwrap_or(None);

        // Note: when we implement the `sync()` method in #28,
        // we will remove this, and `.get()` will return the current content of cache if it
        // is not empty.
        let remote_timestamp = get_latest_change_timestamp(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
        )?;

        if let Some(collection) = stored {
            let up_to_date = collection.timestamp == remote_timestamp;
            if up_to_date && self.verifier.verify(&collection).is_ok() {
                debug!("Local data is up-to-date and valid.");
                return Ok(collection.records);
            }
        }

        info!("Local data is empty, outdated, or has been tampered. Fetch from server.");
        let collection = self._fetch_records_and_verify(remote_timestamp)?;
        let collection_bytes: Vec<u8> = serde_json::to_string(&collection)?.into();
        self.storage.store(&storage_key, collection_bytes)?;
        Ok(collection.records)
    }
}

#[cfg(test)]
mod tests {
    use super::signatures::{SignatureError, Verification};
    use super::{Client, ClientError, Collection};
    use env_logger;
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use serde_json::json;
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;

    struct VerifierWithVerificatonError {}
    struct VerifierWithNoError {}
    struct VerifierWithInvalidSignatureError {}

    impl Verification for VerifierWithVerificatonError {
        fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            return Err(SignatureError::VerificationError {
                name: "signature verification error".to_owned(),
            });
        }
    }

    impl Verification for VerifierWithNoError {
        fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    impl Verification for VerifierWithInvalidSignatureError {
        fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            return Err(SignatureError::InvalidSignature {
                name: "invalid signature error".to_owned(),
            });
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _ = set_backend(&ReqwestBackend);
    }

    fn test_get(
        mock_server: &MockServer,
        mut client: Client,
        latest_change_response: &str,
        records_response: &str,
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

        let actual_result = client.get();
        assert_eq!(1, get_latest_change_mock.times_called());
        assert_eq!(actual_result, expected_result);

        get_changeset_mock.delete();
        get_latest_change_mock.delete();
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

        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(VerifierWithVerificatonError {}))
                .build(),
            valid_latest_change_response,
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#,
            Err(ClientError::VerificationError {
                name: "signature verification error".to_owned(),
            }),
        );

        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(VerifierWithNoError {}))
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
            Ok(vec![json!({
                "id": 1,
                "last_modified": 100
            })]),
        );

        test_get(
            &mock_server,
            Client::builder()
                .server_url(&mock_server_address)
                .collection_name("url-classifier-skip-urls")
                .verifier(Box::new(VerifierWithInvalidSignatureError {}))
                .build(),
            valid_latest_change_response,
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#,
            Err(ClientError::VerificationError {
                name: "invalid signature error".to_owned(),
            }),
        );
    }
}
