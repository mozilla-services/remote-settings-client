
mod kinto_http;
mod signatures;

use log::{debug};
use kinto_http::{get_last_modified_change, get_changeset, KintoObject, KintoError};
use signatures::{DefaultVerifier};
pub use signatures::{SignatureError, Verification};

pub const DEFAULT_SERVER_URL: &str = "https://firefox.settings.services.mozilla.com/v1";
pub const DEFAULT_BUCKET_NAME: &str = "main";

#[derive(Debug, PartialEq)]
pub enum ClientError {
    VerificationError {name: String},
    Error {name: String}
}

impl From<KintoError> for ClientError {
    fn from(err: KintoError) -> Self {
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
            SignatureError::VerificationError {name} => {
                return ClientError::VerificationError{name: name}
            }
            SignatureError::InvalidSignature {name} => {
                return ClientError::Error {name: name}
            }
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
/// # use async_trait::async_trait;
/// struct CustomVerifier{}
/// 
/// # #[async_trait]
/// impl Verification for CustomVerifier {
///    async fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
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
    verifier: Box<dyn Verification> 
}

impl Default for Client {
    fn default() -> Self {
        Client {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(DefaultVerifier{})
        }
    }
}

impl Client {

    fn instantiate_verifier(verifier: Option<Box<dyn Verification>>) -> Box<dyn Verification> {
        return match verifier {
            Some(verifier) => verifier,
            None => Box::new(DefaultVerifier{})
        }
    }

    pub fn create_with_collection(collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier),
            ..Default::default()
        }
    }

    /// Create a Client from a bucket name, collection name and with an optional custom verifier
    pub fn create_with_bucket_collection(bucket_name: &str, collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            bucket_name: bucket_name.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier),
            ..Default::default()
        }
    }
    
    /// Create a Client from a server url, collection name and with an optional custom verifier
    pub fn create_with_server_collection(server_url: &str, collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            server_url: server_url.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier),
            ..Default::default()
        }
    }

    /// Create a Client from a server url, bucket name, collection name and with an optional custom verifier
    pub fn create_with_server_bucket_collection(server_url: &str, bucket_name: &str, collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            server_url: server_url.to_owned(),
            bucket_name: bucket_name.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier)
        }
    }

    /// Fetches records for a given collection from the remote-settings server
    ///
    /// # Examples
    /// ```text
    /// async fn main() {
    ///   match Client::create_with_collection("collection", None).get().await {
    ///     Ok(records) => println!("{:?}", records),
    ///     Err(error) => println!("Could not fetch records: {:?}", error)
    ///   };
    /// }
    /// ```
    /// 
    /// # Errors
    /// If an error occurs while fetching records, ```ClientError``` is returned
    pub async fn get(&self) -> Result<Vec<KintoObject>, ClientError> {

        let expected = get_last_modified_change(&self.server_url, &self.bucket_name, &self.collection_name).await?;

        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            expected
       )
       .await?;

       debug!("changeset.metadata {}", serde_json::to_string_pretty(&changeset.metadata)?);

       // verify the signature
       let collection = Collection {
           bid: self.bucket_name.to_owned(),
           cid: self.collection_name.to_owned(),
           metadata: changeset.metadata,
           records: changeset.changes,
           timestamp: changeset.timestamp
        };

        self.verifier.verify(&collection).await?;
        Ok(collection.records)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use httpmock::Method::{GET};
    use httpmock::{Mock, MockServer};
    use async_trait::async_trait;
    use env_logger;
    use log::{debug};
    use super::signatures::{Verification, SignatureError};
    use super::{Client, Collection, ClientError};

    struct VerifierWithVerificatonError {}
    struct VerifierWithNoError {}
    struct VerifierWithInvalidSignatureError {}

    #[async_trait]
    impl Verification for VerifierWithVerificatonError {
        async fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            return Err(SignatureError::VerificationError{name: "verification error".to_owned()});
        }
    }

    #[async_trait]
    impl Verification for VerifierWithNoError {
        async fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    #[async_trait]
    impl Verification for VerifierWithInvalidSignatureError {
        async fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            return Err(SignatureError::InvalidSignature{name: "invalid signature error".to_owned()});
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();    
    }

    struct Test<'a> {
        test_description: &'a str,
        client: Client,
        changeset_response_body: &'a str,
        expected_result: Result<Vec<serde_json::Value>, ClientError>
    }

    #[tokio::test]
    async fn test_get_verification() {
        init();

        let mock_server = MockServer::start();

        const EXPECTED_VERSION: u64 = 9173;

        let tests = vec![
            Test {
                test_description: "test_get_fails_if_verification_fails_with_verification_error",
                client: Client::create_with_server_collection(&mock_server.url(""), "url-classifier-skip-urls", Some(Box::new(VerifierWithVerificatonError{}))),
                changeset_response_body:  r#"{
                    "metadata": {},
                    "changes": [],
                    "timestamp": 0
                }"#,
                expected_result: Err(ClientError::VerificationError{name: "verification error".to_owned()})
            },
            Test {
                test_description: "test_get_passes_if_verification_passes",
                client: Client::create_with_server_collection(&mock_server.url(""), "url-classifier-skip-urls", Some(Box::new(VerifierWithNoError{}))),
                changeset_response_body: r#"{
                    "metadata": {
                        "data": "test"
                    },
                    "changes": [{
                        "id": 1,
                        "last_modified": 100
                    }],
                    "timestamp": 0
                }"#,
                expected_result: Ok(vec![json!({
                        "id": 1,
                        "last_modified": 100
                    })
                ])
            },
            Test {
                test_description: "test_get_fails_if_verification_fails_with_invalid_signature_error",
                client: Client::create_with_server_collection(&mock_server.url(""), "url-classifier-skip-urls", Some(Box::new(VerifierWithInvalidSignatureError{}))),
                changeset_response_body: r#"{
                    "metadata": {},
                    "changes": [],
                    "timestamp": 0
                }"#,
                expected_result: Err(ClientError::Error{name: "invalid signature error".to_owned()})
            }
        ];

        for test in &tests {

            debug!("test name: {}", test.test_description);

            let mut get_latest_change_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/monitor/collections/changes/records")
            .expect_query_param("bucket", "main")
            .expect_query_param("collection", "url-classifier-skip-urls")
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_header("etag", "12345")
            .return_body(
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
            ).create_on(&mock_server);

            let mut get_changeset_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/buckets/main/collections/url-classifier-skip-urls/changeset")
            .expect_query_param("_expected", &EXPECTED_VERSION.to_string())
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(test.changeset_response_body).create_on(&mock_server);

            let actual_result = test.client.get().await;
            assert_eq!(actual_result, test.expected_result);
            assert_eq!(1, get_changeset_mock.times_called());
            assert_eq!(1, get_latest_change_mock.times_called());

            get_changeset_mock.delete();
            get_latest_change_mock.delete();
        }

    }
}