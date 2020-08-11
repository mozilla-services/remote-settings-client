/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject};
use log::debug;
pub use signatures::{SignatureError, Verification};

#[cfg(feature = "openssl_verifier")]
use crate::client::signatures::openssl_verifier::OpenSSLVerifier as AlwaysAcceptsVerifier;

#[cfg(not(feature = "openssl_verifier"))]
use crate::client::signatures::default_verifier::DefaultVerifier as AlwaysAcceptsVerifier;

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
}

impl Default for Client {
    fn default() -> Self {
        return Client {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(AlwaysAcceptsVerifier{}),
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
        let expected = get_latest_change_timestamp(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
        )?;

        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            expected
       )?;

       debug!("changeset.metadata {}", serde_json::to_string_pretty(&changeset.metadata)?);

       // verify the signature
       let collection = Collection {
           bid: self.bucket_name.to_owned(),
           cid: self.collection_name.to_owned(),
           metadata: changeset.metadata,
           records: changeset.changes,
           timestamp: changeset.timestamp
        };

        self.verifier.verify(&collection)?;
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
