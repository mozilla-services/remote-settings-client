mod kinto_http;
mod signatures;
mod canonical_json;

use async_trait::async_trait;
use canonical_json::serialize;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::nid::Nid;
use openssl::x509::X509;

use base64;
use reqwest;
use serde_json::json;
use signatory::{
    ecdsa::{curve::NistP384, FixedSignature},
    verify_sha384, EcdsaPublicKey, Signature,
};
use signatory_ring::ecdsa::P384Verifier;

use kinto_http::{get_changeset, KintoObject, KintoError};
use signatures::{Verification, SignatureError};

#[derive(Debug)]
pub enum ClientError {}

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
        err.into()
    }
}

pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<KintoObject>,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct Client {
    server_url: String,
    bucket_id: String,
    collection_name: String,
    // for consistency, either we should bucket_name or collection_id
    // (or bid/cid, or bucket/collection)
}

impl Default for Client {

    fn default() -> Self {
        Client {
            server_url: "https://firefox.settings.services.mozilla.com/v1".to_string(),
            bucket_id: "main".to_string(),
            collection_name: "".to_string()
        }
    }

}

#[async_trait]
// This should probably go to signatures.rs
impl Verification for Client {
    async fn verify(collection: &Collection) -> Result<(), SignatureError> {

        println!("In Verfication!");
        // Fetch certificate PEM (public key).
        let x5u = collection.metadata["signature"]["x5u"].as_str().unwrap();
        let resp = reqwest::get(&x5u.to_string()).await?;
        let pem = resp.bytes().await?;

        // Parse PEM (OpenSSL)
        let cert = X509::from_pem(&pem)?;
        let public_key = cert.public_key()?;
        let ec_public_key = public_key.ec_key()?;
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let public_key_bytes = ec_public_key.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;
        let pk: EcdsaPublicKey<NistP384> = EcdsaPublicKey::from_bytes(&public_key_bytes)?;

        // Instantiate signature
        let b64_signature = collection.metadata["signature"]["signature"]
            .as_str()
            .unwrap_or("");
        let signature_bytes = base64::decode_config(&b64_signature, base64::URL_SAFE)?;
        let signature = FixedSignature::<NistP384>::from_bytes(&signature_bytes)?;

        // Serialized data.
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by(|a, b| (a["id"]).to_string().cmp(&b["id"].to_string()));
        let serialized = serialize(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string().to_owned()
        }));
        let data = format!("Content-Signature:\x00{}", serialized);

        // Verify
        verify_sha384(&P384Verifier::from(&pk), &data.as_bytes(), &signature)?;

        Ok(())
    }
}

impl Client {

    pub async fn create_with_collection(collection_name: &str) -> Self {
        println!("The collection name is {}", collection_name);

        let client = Client {
            collection_name: collection_name.to_string(),
            ..Default::default()
        };

        println!("{:?}", client);
        return client
    }

    // missing create_with_server_collection()

    pub async fn create_with_bucket_collection(bucket_id: &str, collection_name: &str) -> Self {
        println!("The bucket id is {}", bucket_id);
        println!("The collection name is {}", collection_name);

        let client = Client {
            bucket_id: bucket_id.to_string(),
            collection_name: collection_name.to_string(),
            ..Default::default()
        };

        println!("{:?}", client);
        return client
    }

    pub async fn create_with_server_bucket_collection(server_url: &str, bucket_id: &str, collection_name: &str) -> Self {
        println!("The server url is {}", server_url);
        println!("The bucket id is {}", bucket_id);
        println!("The collection name is {}", collection_name);

        let client = Client {
            server_url: server_url.to_string(),
            bucket_id: bucket_id.to_string(),
            collection_name: collection_name.to_string(),
        };

        println!("{:?}", client);
        return client
    }

    // For parameter expected, default value is 0
    // Where is this default defined?
    pub async fn get(&self, expected: u64) -> Result<Collection, ClientError> {
        // if expected is None or 0, we could fetch the latest value
        // use the monitor/changes collection.
        // get_record(&self.server_url, "monitor", "changes", expected=random for cache busting)
        // and then lookup entries where bucket == self.bucket_id and collection == self.collection_name
        // and use the `last_modified` as the `expected` value here.

        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_id,
            &self.collection_name,
            expected,
       )
       .await?;

       println!("changeset.metadata {}", serde_json::to_string_pretty(&changeset.metadata)?);

       let collection = Collection {
           bid: self.bucket_id.to_string(),
           cid: self.collection_name.to_string(),
           metadata: changeset.metadata,
           records: changeset.changes,
           timestamp: changeset.timestamp
        };

        Client::verify(&collection).await?;

        println!("verification done successfully!");

        Ok(collection)
    }

}
