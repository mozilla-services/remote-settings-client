mod kinto_http;
mod signatures;

use kinto_http::{get_changeset, KintoObject, KintoError};
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

#[derive(Debug, PartialEq)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<KintoObject>,
    pub timestamp: u64,
}

pub struct Client {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    // Box<dyn Trait> is necessary since implementation of Verification can be of any size unknown at compile time
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

    pub fn create_with_bucket_collection(bucket_name: &str, collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            bucket_name: bucket_name.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier),
            ..Default::default()
        }
    }
    
    pub fn create_with_server_collection(server_url: &str, collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            server_url: server_url.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier),
            ..Default::default()
        }
    }

    pub fn create_with_server_bucket_collection(server_url: &str, bucket_name: &str, collection_name: &str, verifier: Option<Box<dyn Verification>>) -> Self {
        return Client {
            server_url: server_url.to_owned(),
            bucket_name: bucket_name.to_owned(),
            collection_name: collection_name.to_owned(),
            verifier: Client::instantiate_verifier(verifier)
        }
    }

    // For parameter expected, default value is 0
    pub async fn get(&self, expected: u64) -> Result<Vec<KintoObject>, ClientError> {
        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            expected,
       )
       .await?;

       println!("changeset.metadata {}", serde_json::to_string_pretty(&changeset.metadata)?);

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
    use httpmock::Method::GET;
    use httpmock::{mock, with_mock_server};
    use async_trait::async_trait;
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

    #[tokio::test]
    #[with_mock_server]
    async fn test_get_fails_if_verification_fails_with_verification_error() {
        let get_changeset_mock = mock(GET, "/buckets/main/collections/url-classifier-skip-urls/changeset")
        .expect_query_param("_expected", "0")
        .return_status(200)
        .return_header("Content-Type", "application/json")
        .return_body(
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#
        ).create();

        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithVerificatonError{}))).get(0).await;
        let expected_result = Err(ClientError::VerificationError{name: "verification error".to_owned()});
        assert_eq!(1, get_changeset_mock.times_called());
        assert_eq!(expected_result, actual_result);
    }

    #[tokio::test]
    #[with_mock_server]
    async fn test_get_passes_if_verification_passes() {
        let expected_version: u64 = 10;

        let get_changeset_mock = mock(GET, "/buckets/main/collections/url-classifier-skip-urls/changeset")
        .expect_query_param("_expected", &expected_version.to_string())
        .return_status(200)
        .return_header("Content-Type", "application/json")
        .return_body(
            r#"{
                "metadata": {
                    "data": "test"
                },
                "changes": [{
                    "id": 1,
                    "last_modified": 100
                }],
                "timestamp": 0
            }"#
        ).create();

        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithNoError{}))).get(expected_version).await;
        assert_eq!(1 , get_changeset_mock.times_called());

        match actual_result {
            Ok(records) => {
                assert_eq!(
                    vec![
                        json!({
                            "id": 1,
                            "last_modified": 100
                        })
                    ], records
                )
            },
            Err(error) => panic!("invalid response : {:?}", error)
        };
    }

    #[tokio::test]
    #[with_mock_server]
    async fn test_get_fails_if_verification_fails_with_invalid_signature_error() {
        let get_changeset_mock = mock(GET, "/buckets/main/collections/url-classifier-skip-urls/changeset")
        .expect_query_param("_expected", "0")
        .return_status(200)
        .return_header("Content-Type", "application/json")
        .return_body(
            r#"{
                "metadata": {},
                "changes": [],
                "timestamp": 0
            }"#
        ).create();

        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithInvalidSignatureError{}))).get(0).await;
        let expected_result = Err(ClientError::Error{name: "invalid signature error".to_owned()});
        assert_eq!(expected_result, actual_result);
        assert_eq!(1, get_changeset_mock.times_called());
    }
}
