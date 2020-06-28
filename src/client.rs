mod kinto_http;
mod signatures;

use kinto_http::{get_changeset, KintoObject, KintoError};
use signatures::{DefaultVerifier};
use std::collections::HashMap;
use serde_json::Value;
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

    fn matches(record: &KintoObject, filters: &HashMap<&str, serde_json::Value>) -> bool {

        for (key, value) in filters {
            let org_value = match (*record).get(key) {
                Some(value) => value,
                None => return false
            };

            match(org_value, value) {
                (Value::Null, Value::Null) => continue,
                (Value::Bool(b1), Value::Bool(b2)) => {
                    if b1 == b2 { continue } else { return false }
                },
                (Value::Number(number1), Value::Number(number2)) => {
                    if number1 == number2 { continue } else { return false }
                },
                (Value::String(string1), Value::String(string2)) => {
                    if string1 == string2 { continue } else { return false }
                },
                (Value::Array(vector1), Value::Array(vector2)) => {
                    if vector1 == vector2 { continue } else { return false }
                },
                (Value::Object(hashmap1), Value::Object(hashmap2)) => {
                    if hashmap1 == hashmap2 { continue } else { return false }
                },
                _ => return false
            };
        }

        return true;
    }

    pub async fn get(&self, expected: u64, filters: std::collections::HashMap<&str, serde_json::value::Value>) -> Result<Collection, ClientError> {
        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            expected,
       )
       .await?;

       println!("changeset.metadata {}", serde_json::to_string_pretty(&changeset.metadata)?);

        // filter collection records
       let mut filtered_records = Vec::new();

       for record in changeset.changes {
           if Client::matches(&record, &filters) {
               filtered_records.push(record);
           }
       }

       let collection = Collection {
           bid: self.bucket_name.to_string(),
           cid: self.collection_name.to_string(),
           metadata: changeset.metadata,
           records: filtered_records,
           timestamp: changeset.timestamp
        };

        self.verifier.verify(&collection).await?;
        Ok(collection)
    }
    
    // For parameter expected, default value is 0
    pub async fn get_all(&self, expected: u64) -> Result<Collection, ClientError> {
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
        Ok(collection)
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
    use std::collections::HashMap;

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

        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithVerificatonError{}))).get_all(0).await;
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

        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithNoError{}))).get_all(expected_version).await;
        assert_eq!(1 , get_changeset_mock.times_called());

        match actual_result {
            Ok(collection) => {
                assert_eq!(
                    Collection {
                        bid: "main".to_owned(),
                        cid: "url-classifier-skip-urls".to_owned(),
                        metadata: json!({
                            "data": "test".to_owned()
                        }),
                        records: vec![
                            json!({
                                "id": 1,
                                "last_modified": 100
                            })
                        ],
                        timestamp: 0
                    }, collection
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

        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithInvalidSignatureError{}))).get_all(0).await;
        let expected_result = Err(ClientError::Error{name: "invalid signature error".to_owned()});
        assert_eq!(expected_result, actual_result);
        assert_eq!(1, get_changeset_mock.times_called());
    }

    #[test]
    fn test_matches_returns_false_mismatching_object_and_null_value_types() {

        let record = json!({"id": json!({"nested": 2})});
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }
    
    #[test]
    fn test_matches_returns_false_mismatching_bool_and_null_value_types() {

        let record = json!(true);
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_number_and_null_value_types() {

        let record = json!(12);
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_string_and_null_value_types() {

        let record = json!("does not match");
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_array_and_null_value_types() {

        let record = json!(vec![1,2,3]);
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_bool_and_array_value_types() {

        let record = json!(vec![1,2,3]);
        let mut filters = HashMap::new();
        filters.insert("id", json!(true));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_bool_and_number_value_types() {

        let record = json!(123);
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_bool_and_string_value_types() {

        let record = json!("does not match");
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_bool_and_object_value_types() {

        let record = json!({"id": 2});
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_number_and_string_value_types() {

        let record = json!("does not match");
        let mut filters = HashMap::new();
        filters.insert("id", json!(123));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_number_and_array_value_types() {

        let record = json!(vec![1,2,3]);
        let mut filters = HashMap::new();
        filters.insert("id", json!(123));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_number_and_object_value_types() {

        let record = json!({"id": 1});
        let mut filters = HashMap::new();
        filters.insert("id", json!(123));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_string_and_array_value_types() {

        let record = json!(vec!["does not match", "matches", "I don't know"]);
        let mut filters = HashMap::new();
        filters.insert("id", json!("does not match"));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_string_and_object_value_types() {

        let record = json!({"matches": "does not match"});
        let mut filters = HashMap::new();
        filters.insert("id", json!("does not match"));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_returns_false_mismatching_object_and_array_value_types() {

        let record = json!({"id": 1, "matches": false});
        let mut filters = HashMap::new();
        filters.insert("id", json!(vec![1,2,3]));

        assert_eq!(Client::matches(&record, &filters), false);
    }

    #[test]
    fn test_matches_correctly_matches_null_values() {

        let record = json!({"id": json!(null), "nested": {"id": 2, "name": "vishwa"}});
        let mut filters = HashMap::new();
        filters.insert("id", json!(null));
        filters.insert("nested", json!({"id": 2, "name": "vishwa"}));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[test]
    fn test_matches_correctly_matches_bool_values() {

        let record = json!({"matches": true});
        let mut filters = HashMap::new();
        filters.insert("matches", json!(true));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[test]
    fn test_matches_correctly_matches_number_values() {

        let record = json!({"number": json!(123)});
        let mut filters = HashMap::new();
        filters.insert("number", json!(123));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[test]
    fn test_matches_correctly_matches_string_values() {

        let record = json!({"string": json!("test")});
        let mut filters = HashMap::new();
        filters.insert("string", json!("test"));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[test]
    fn test_matches_correctly_matches_array_values() {

        let record = json!({"array": json!(vec!["one","two","three"])});
        let mut filters = HashMap::new();
        filters.insert("array", json!(vec!["one","two","three"]));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[test]
    fn test_matches_correctly_matches_object_values() {

        let record = json!({"object": json!({"id": 1, "nested_object": json!({"id": 2})})});
        let mut filters = HashMap::new();
        filters.insert("object", json!({"id": 1, "nested_object": json!({"id": 2})}));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[test]
    fn test_matches_correctly_matches_array_of_object_values() {

        let record = json!({"array": json!(vec![json!({"id": 1}), json!({"id": 2})])});
        let mut filters = HashMap::new();
        filters.insert("array", json!(vec![json!({"id": 1}), json!({"id": 2})]));

        assert_eq!(Client::matches(&record, &filters), true);
    }

    #[tokio::test]
    #[with_mock_server]
    async fn test_get_correctly_filters_records() {

        let get_changeset_mock = mock(GET, "/buckets/main/collections/url-classifier-skip-urls/changeset")
        .expect_query_param("_expected", "0")
        .return_status(200)
        .return_header("Content-Type", "application/json")
        .return_body(
            r#"{
                "metadata": {"data": "test"},
                "changes": [
                    {
                        "id": 1,
                        "last_modified": 100
                    },
                    {
                        "id": 2,
                        "last_modified": 200
                    }
                ],
                "timestamp": 0
            }"#
        ).create();

        let mut filters: HashMap<&str, serde_json::value::Value> = HashMap::new();
        filters.insert("id", json!(2));
        filters.insert("last_modified", json!(200));

        let expected_version: u64 = 0;
    
        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithNoError{})))
                                    .get(expected_version, filters).await;

        assert_eq!(1, get_changeset_mock.times_called());
        
        match actual_result {
            Ok(collection) => {
                assert_eq!(
                    Collection {
                        bid: "main".to_owned(),
                        cid: "url-classifier-skip-urls".to_owned(),
                        metadata: json!({
                            "data": "test".to_owned()
                        }),
                        records: vec![
                            json!({
                                "id": 2,
                                "last_modified": 200
                            })
                        ],
                        timestamp: 0
                    }, collection
                )
            },
            Err(error) => panic!("invalid response : {:?}", error)
        };
    }

    #[tokio::test]
    #[with_mock_server]
    async fn test_get_correctly_returns_all_records_when_no_filters_present() {
        let get_changeset_mock = mock(GET, "/buckets/main/collections/url-classifier-skip-urls/changeset")
        .expect_query_param("_expected", "0")
        .return_status(200)
        .return_header("Content-Type", "application/json")
        .return_body(
            r#"{
                "metadata": {"data": "test"},
                "changes": [
                    {
                        "id": 1,
                        "last_modified": 100
                    },
                    {
                        "id": 2,
                        "last_modified": 200
                    }
                ],
                "timestamp": 0
            }"#
        ).create();

        let expected_version: u64 = 0;
    
        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithNoError{})))
                                    .get(expected_version, HashMap::new()).await;

        assert_eq!(1, get_changeset_mock.times_called());
        
        match actual_result {
            Ok(collection) => {
                assert_eq!(
                    Collection {
                        bid: "main".to_owned(),
                        cid: "url-classifier-skip-urls".to_owned(),
                        metadata: json!({
                            "data": "test".to_owned()
                        }),
                        records: vec![
                            json!({
                                "id": 1,
                                "last_modified": 100
                            }),
                            json!({
                                "id": 2,
                                "last_modified": 200
                            })
                        ],
                        timestamp: 0
                    }, collection
                )
            },
            Err(error) => panic!("invalid response : {:?}", error)
        };
    }

    #[tokio::test]
    #[with_mock_server]
    async fn test_get_correctly_returns_no_records_when_no_record_matches_filters() {
        let get_changeset_mock = mock(GET, "/buckets/main/collections/url-classifier-skip-urls/changeset")
        .expect_query_param("_expected", "0")
        .return_status(200)
        .return_header("Content-Type", "application/json")
        .return_body(
            r#"{
                "metadata": {"data": "test"},
                "changes": [
                    {
                        "id": 1,
                        "last_modified": 100
                    },
                    {
                        "id": 2,
                        "last_modified": 200
                    }
                ],
                "timestamp": 0
            }"#
        ).create();

        let mut filters: HashMap<&str, serde_json::Value> = HashMap::new();

        filters.insert("id", json!(3));

        let expected_version: u64 = 0;
    
        let actual_result = Client::create_with_server_collection("http://localhost:5000", "url-classifier-skip-urls", Some(Box::new(VerifierWithNoError{})))
                                    .get(expected_version, filters).await;

        assert_eq!(1, get_changeset_mock.times_called());
        
        match actual_result {
            Ok(collection) => {
                assert_eq!(
                    Collection {
                        bid: "main".to_owned(),
                        cid: "url-classifier-skip-urls".to_owned(),
                        metadata: json!({
                            "data": "test".to_owned()
                        }),
                        records: vec![],
                        timestamp: 0
                    }, collection
                )
            },
            Err(error) => panic!("invalid response : {:?}", error)
        };
    }
}
