/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;
mod storage;

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject, ChangesetResponse};
use log::debug;
use serde_json::json;
pub use signatures::{SignatureError, Verification};
pub use storage::{RemoteStorage, RemoteStorageError};

#[cfg(feature = "openssl_verifier")]
use crate::client::signatures::openssl_verifier::OpenSSLVerifier as AlwaysAcceptsVerifier;

#[cfg(not(feature = "openssl_verifier"))]
use crate::client::signatures::default_verifier::DefaultVerifier as AlwaysAcceptsVerifier;

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
            KintoError::Error { name } => return ClientError::Error { name: name },
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

impl From<SignatureError> for ClientError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::VerificationError { name } => {
                return ClientError::VerificationError { name: name }
            }
            SignatureError::InvalidSignature { name } => return ClientError::Error { name: name },
        }
    }
}

/// Response body from remote-settings server
#[derive(Debug, PartialEq)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<KintoObject>,
    pub timestamp: u64,
}

/// Handles requests to Remote-Settings
/// # Examples
/// Create Client with collection_name and without custom Verifier
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::{Client, Collection};
/// # fn main() {
///   let client = Client::create_with_collection("collection_name", None);
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
///    fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
///        Ok(()) // everything is verified!
///    }
/// }
///
/// # fn main() {
///   let client = Client::create_with_collection("collection_name", Some(Box::new(CustomVerifier{})));
/// # }
/// ```
pub struct Client {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    verifier: Box<dyn Verification>,
    cache: Box<dyn RemoteStorage>,
}

impl Default for Client {
    fn default() -> Self {
        return Client {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(AlwaysAcceptsVerifier{}),
            cache: Box::new(DefaultCache{}),
        };
    }
}

impl Client {

    pub fn create_with_collection(
        collection_name: &str,
        verifier: Option<Box<dyn Verification>>,
    ) -> Self {
        return Client {
            collection_name: collection_name.to_owned(),
            verifier: verifier.unwrap_or_else(|| Box::new(AlwaysAcceptsVerifier{})),
            ..Default::default()
        };
    }

    /// Create a Client from a bucket name, collection name and with an optional custom verifier
    pub fn create_with_bucket_collection(
        bucket_name: &str,
        collection_name: &str,
        verifier: Option<Box<dyn Verification>>,
    ) -> Self {
        return Client {
            bucket_name: bucket_name.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: verifier.unwrap_or_else(|| Box::new(AlwaysAcceptsVerifier{})),
            ..Default::default()
        };
    }

    /// Create a Client from a server url, collection name and with an optional custom verifier
    pub fn create_with_server_collection(
        server_url: &str,
        collection_name: &str,
        verifier: Option<Box<dyn Verification>>,
    ) -> Self {
        return Client {
            server_url: server_url.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: verifier.unwrap_or_else(|| Box::new(AlwaysAcceptsVerifier{})),
            ..Default::default()
        };
    }

    /// Create a Client from a server url, bucket name, collection name and with an optional custom verifier
    pub fn create_with_server_bucket_collection(
        server_url: &str,
        bucket_name: &str,
        collection_name: &str,
        verifier: Option<Box<dyn Verification>>,
    ) -> Self {
        return Client {
            server_url: server_url.to_owned(),
            bucket_name: bucket_name.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: verifier.unwrap_or_else(|| Box::new(AlwaysAcceptsVerifier{})),
            cache: Box::new(DefaultCache{}),
        };
    }

    fn fetch_records_with_verification(&self) -> Result<Vec<KintoObject>, ClientError> {

        let remote_timestamp = self.get_latest_collection_timestamp()?;

        let changeset_response = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            remote_timestamp,
        )?;

        debug!("changeset.metadata {}", serde_json::to_string_pretty(&changeset_response.metadata)?);

        let collection: Collection = self.create_collection_from_response(changeset_response);
        self.verifier.verify(&collection)?;

        // before returning records, we want to override it into the cache
        self.cache.store(&format!("{}/{}", collection.bid, collection.cid), json!(collection.records))?;
        Ok(collection.records)
    }

    fn get_latest_collection_timestamp(&self) -> Result<u64, ClientError> {
        let expected = get_latest_change_timestamp(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
        )?;
        
        Ok(expected)
    }

    fn create_collection_from_response(&self, change_set_response: ChangesetResponse) -> Collection {
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
    ///   match Client::create_with_collection("collection", None).get() {
    ///     Ok(records) => println!("{:?}", records),
    ///     Err(error) => println!("Error fetching/verifying records: {:?}", error)
    ///   };
    /// }
    /// ```
    ///
    /// # Errors
    /// If an error occurs while fetching records, ```ClientError``` is returned
    pub fn get(&self) -> Result<Vec<KintoObject>, ClientError> {

        // If storage is empty for this bucket/collection, fetch from .../changeset, validate signature, store locally, and return records
        // Otherwise, obtain current remote timestamp of collection from server (done in #26)
        // If remote timestamp is different than local, fetch, validate signature, overwrite local existing data and return records
        // If remote timestamp is same as local, validate signature and return records. If validating signature fails, fetch, validate, overwrite, and return records.

        let key = format!("{}/{}", self.bucket_name, self.collection_name);
        match self.cache.retrieve(&key) {
            Ok(value) => {
                // convert JSON object to LatestChangeResponse object
                let cached_change_response: ChangesetResponse = serde_json::from_value(value)?;
                
                let remote_timestamp = self.get_latest_collection_timestamp()?;
                
                if remote_timestamp != cached_change_response.timestamp {
                    // fetch records, validate signature, overwrite local existing data and return records
                    let records = self.fetch_records_with_verification()?;
                    return Ok(records)
                }

                // otherwise just validate signature and return records but if valdiation fails, then fetch, validate, overwrite and return records
                let collection = self.create_collection_from_response(cached_change_response);
                let records = match self.verifier.verify(&collection) {
                    Ok(()) => collection.records,
                    Err(_err) => {
                        let records = self.fetch_records_with_verification()?;
                        records
                    },
                };

                return Ok(records)
            },
            Err(err) => {
                debug!("error - {:?} : accessing key={} from cache - fetching records from server", err, key);
                
                let records = self.fetch_records_with_verification()?;
                return Ok(records)
            }
        }
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
        set_backend(&ReqwestBackend).unwrap();
    }

    fn test_get(
        mock_server: &MockServer,
        client: Client,
        latest_change_response: &str,
        records_response: &str,
        expected_result: Result<Vec<serde_json::Value>, ClientError>,
    ) {
        let mut get_latest_change_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/monitor/collections/changes/records")
            .expect_query_param("bucket", "main")
            .expect_query_param("collection", "url-classifier-skip-urls")
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
    fn test_get_verification() {
        init();

        let mock_server = MockServer::start();

        let mock_server_address = mock_server.url("");

        let valid_latest_change_response = &format!(
            "{}",
            r#"{
            "data": [
                {
                    "id": "123",
                    "last_modified": 9173,
                    "bucket":"main",
                    "collection":"url-classifier-skip-urls",
                    "host":"localhost:5000"
                }
            ]
        }"#
        );

        test_get(
            &mock_server,
            Client::create_with_server_collection(
                &mock_server_address,
                "url-classifier-skip-urls",
                Some(Box::new(VerifierWithVerificatonError {})),
            ),
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
            Client::create_with_server_collection(
                &mock_server_address,
                "url-classifier-skip-urls",
                Some(Box::new(VerifierWithNoError {})),
            ),
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
            Client::create_with_server_collection(
                &mock_server_address,
                "url-classifier-skip-urls",
                Some(Box::new(VerifierWithInvalidSignatureError {})),
            ),
            valid_latest_change_response,
            r#"{
            "metadata": {},
            "changes": [],
            "timestamp": 0
        }"#,
            Err(ClientError::Error {
                name: "invalid signature error".to_owned(),
            }),
        );

        test_get(&mock_server,Client::create_with_server_collection(
            &mock_server_address,
            "url-classifier-skip-urls",
            Some(Box::new(VerifierWithNoError {})),
        ), &format!(
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
