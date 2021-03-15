/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;

use serde::Serialize;

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject};
pub use signatures::{SignatureError, Verification};

#[cfg(feature = "ring_verifier")]
use crate::client::signatures::ring_verifier::RingVerifier as DefaultVerifier;

#[cfg(not(feature = "ring_verifier"))]
use crate::client::signatures::default_verifier::DefaultVerifier;

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

impl From<SignatureError> for ClientError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::CertificateError { name } => ClientError::VerificationError { name },
            SignatureError::VerificationError { name } => ClientError::VerificationError { name },
            SignatureError::InvalidSignature { name } => ClientError::VerificationError { name },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Record(serde_json::Value);

impl Record {
    pub fn new(value: serde_json::Value) -> Record {
        Record(value)
    }

    // Return the underlying [`serde_json::Value`].
    pub fn as_object(&self) -> &serde_json::Map<String, serde_json::Value> {
        // Record data is always an object.
        &self.0.as_object().unwrap()
    }

    // Return the record id.
    pub fn id(&self) -> &str {
        // `id` field is always present as a string.
        self.as_object().get("id").unwrap().as_str().unwrap()
    }

    // Return the record timestamp.
    pub fn last_modified(&self) -> u64 {
        // `last_modified` field is always present as a uint.
        self.as_object()
            .get("last_modified")
            .unwrap()
            .as_u64()
            .unwrap()
    }

    // Return true if the record is a tombstone.
    pub fn deleted(&self) -> bool {
        match self.as_object().get("deleted") {
            Some(v) => v.as_bool().unwrap_or(false),
            None => false,
        }
    }

    // Return a field value.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.as_object().get(key)
    }
}

impl<I> std::ops::Index<I> for Record
where
    I: serde_json::value::Index,
{
    type Output = serde_json::Value;
    fn index(&self, index: I) -> &serde_json::Value {
        static NULL: serde_json::Value = serde_json::Value::Null;
        index.index_into(&self.0).unwrap_or(&NULL)
    }
}

/// Representation of a collection on the server
#[derive(Debug, PartialEq)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<Record>,
    pub timestamp: u64,
}

pub struct ClientBuilder {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    verifier: Box<dyn Verification>,
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

    /// Build Client from ClientBuilder
    pub fn build(self) -> Client {
        Client {
            server_url: self.server_url,
            bucket_name: self.bucket_name,
            collection_name: self.collection_name,
            verifier: self.verifier,
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
}

impl Default for Client {
    fn default() -> Self {
        Client {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(DefaultVerifier {}),
        }
    }
}

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
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
    /// # let client = Client::builder().collection_name("url-classifier-skip-urls").build();
    /// match client.get() {
    ///   Ok(records) => println!("{:?}", records),
    ///   Err(error) => println!("Error fetching/verifying records: {:?}", error)
    /// };
    /// # }
    /// ```
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn get(&self) -> Result<Vec<Record>, ClientError> {
        let expected = get_latest_change_timestamp(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
        )?;

        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            Some(expected),
        )?;

        let records = changeset
            .changes
            .iter()
            .map(|v| Record::new(v.to_owned()))
            .collect();

        let collection = Collection {
            bid: self.bucket_name.to_owned(),
            cid: self.collection_name.to_owned(),
            metadata: changeset.metadata,
            records,
            timestamp: changeset.timestamp,
        };

        self.verifier.verify(&collection)?;

        Ok(collection.records)
    }
}

#[cfg(test)]
mod tests {
    use super::signatures::{SignatureError, Verification};
    use super::{Client, ClientError, Collection, Record};
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
        client: Client,
        latest_change_response: &str,
        records_response: &str,
        expected_result: Result<Vec<Record>, ClientError>,
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
            Ok(vec![Record(json!({
                "id": 1,
                "last_modified": 100
            }))]),
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

    #[test]
    fn test_record_fields() {
        let r = Record(json!({
            "id": "abc",
            "last_modified": 100,
            "foo": {"bar": 42},
            "pi": "3.14"
        }));

        assert_eq!(r.id(), "abc");
        assert_eq!(r.last_modified(), 100);
        assert_eq!(r.deleted(), false);

        // Access fields by index
        assert_eq!(r["pi"].as_str(), Some("3.14"));
        assert_eq!(r["foo"]["bar"].as_u64(), Some(42));
        assert_eq!(r["bar"], serde_json::Value::Null);

        // Or by get() as optional value
        assert_eq!(r.get("bar"), None);
        assert_eq!(r.get("pi").unwrap().as_str(), Some("3.14"));
        assert_eq!(r.get("pi").unwrap().as_f64(), None);
        assert_eq!(r.get("foo").unwrap().get("bar").unwrap().as_u64(), Some(42));

        let r = Record(json!({
            "id": "abc",
            "last_modified": 100,
            "deleted": true
        }));
        assert_eq!(r.deleted(), true);

        let r = Record(json!({
            "id": "abc",
            "last_modified": 100,
            "deleted": "foo"
        }));
        assert_eq!(r.deleted(), false);
    }
}
