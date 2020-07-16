/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;

use kinto_http::{get_changeset, KintoError, KintoObject};
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
    /// # Parameter `expected`
    /// - default value is 0
    /// - used for cache busting
    ///
    /// # Examples
    /// ```text
    /// fn main() {
    ///   let expected: u64 = 0;
    ///   match Client::create_with_collection("collection", None).get(expected) {
    ///     Ok(records) => println!("{:?}", records),
    ///     Err(error) => println!("Could not fetch records: {:?}", error)
    ///   };
    /// }
    /// ```
    ///
    /// # Errors
    /// If an error occurs while fetching records, ```ClientError``` is returned
    pub fn get(&self, expected: u64) -> Result<Vec<KintoObject>, ClientError> {
        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            expected,
        )?;

        debug!(
            "changeset.metadata {}",
            serde_json::to_string_pretty(&changeset.metadata)?
        );

        // verify the signature
        let collection = Collection {
            bid: self.bucket_name.to_owned(),
            cid: self.collection_name.to_owned(),
            metadata: changeset.metadata,
            records: changeset.changes,
            timestamp: changeset.timestamp,
        };

        self.verifier.verify(&collection)?;
        Ok(collection.records)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::signatures::{SignatureError, Verification};
//     use super::{Client, ClientError, Collection};
//     use httpmock::Method::GET;
//     use serde_json::json;

//     struct VerifierWithVerificatonError {}
//     struct VerifierWithNoError {}
//     struct VerifierWithInvalidSignatureError {}

//     impl Verification for VerifierWithVerificatonError {
//         fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
//             return Err(SignatureError::VerificationError {
//                 name: "verification error".to_owned(),
//             });
//         }
//     }

//     impl Verification for VerifierWithNoError {
//         fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
//             Ok(())
//         }
//     }

//     impl Verification for VerifierWithInvalidSignatureError {
//         fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
//             return Err(SignatureError::InvalidSignature {
//                 name: "invalid signature error".to_owned(),
//             });
//         }
//     }

//     fn test_get_fails_if_verification_fails_with_verification_error() {
//         let get_changeset_mock = mock(
//             GET,
//             "/buckets/main/collections/url-classifier-skip-urls/changeset",
//         )
//         .expect_query_param("_expected", "0")
//         .return_status(200)
//         .return_header("Content-Type", "application/json")
//         .return_body(
//             r#"{
//                 "metadata": {},
//                 "changes": [],
//                 "timestamp": 0
//             }"#,
//         )
//         .create();

//         let actual_result = Client::create_with_server_collection(
//             "http://localhost:5000",
//             "url-classifier-skip-urls",
//             Some(Box::new(VerifierWithVerificatonError {})),
//         )
//         .get(0);

//         let expected_result = Err(ClientError::VerificationError {
//             name: "verification error".to_owned(),
//         });
//         assert_eq!(1, get_changeset_mock.times_called());
//         assert_eq!(expected_result, actual_result);
//     }

//     fn test_get_passes_if_verification_passes() {
//         let expected_version: u64 = 10;

//         let get_changeset_mock = mock(
//             GET,
//             "/buckets/main/collections/url-classifier-skip-urls/changeset",
//         )
//         .expect_query_param("_expected", &expected_version.to_string())
//         .return_status(200)
//         .return_header("Content-Type", "application/json")
//         .return_body(
//             r#"{
//                 "metadata": {
//                     "data": "test"
//                 },
//                 "changes": [{
//                     "id": 1,
//                     "last_modified": 100
//                 }],
//                 "timestamp": 0
//             }"#,
//         )
//         .create();

//         let actual_result = Client::create_with_server_collection(
//             "http://localhost:5000",
//             "url-classifier-skip-urls",
//             Some(Box::new(VerifierWithNoError {})),
//         )
//         .get(expected_version);
//         assert_eq!(1, get_changeset_mock.times_called());

//         match actual_result {
//             Ok(records) => assert_eq!(
//                 vec![json!({
//                     "id": 1,
//                     "last_modified": 100
//                 })],
//                 records
//             ),
//             Err(error) => panic!("invalid response : {:?}", error),
//         };
//     }

//     fn test_get_fails_if_verification_fails_with_invalid_signature_error() {
//         let get_changeset_mock = mock(
//             GET,
//             "/buckets/main/collections/url-classifier-skip-urls/changeset",
//         )
//         .expect_query_param("_expected", "0")
//         .return_status(200)
//         .return_header("Content-Type", "application/json")
//         .return_body(
//             r#"{
//                 "metadata": {},
//                 "changes": [],
//                 "timestamp": 0
//             }"#,
//         )
//         .create();

//         let actual_result = Client::create_with_server_collection(
//             "http://localhost:5000",
//             "url-classifier-skip-urls",
//             Some(Box::new(VerifierWithInvalidSignatureError {})),
//         )
//         .get(0);

//         let expected_result = Err(ClientError::Error {
//             name: "invalid signature error".to_owned(),
//         });
//         assert_eq!(expected_result, actual_result);
//         assert_eq!(1, get_changeset_mock.times_called());
//     }
// }
