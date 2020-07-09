use crate::client::Collection;

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
use reqwest::Error as ReqwestError;

/// A trait for giving a type a custom signature verifier
/// 
/// Sometimes, you want to use your own verification implementation to verify signature retrieved from the remote-settings server
/// 
/// # How can I implement ```Verification```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::client::Collection;
/// # use async_trait::async_trait;
/// struct SignatureVerifier {}
/// 
/// #[async_trait]
/// impl Verification for SignatureVerifier {
///     async fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait Verification {

    /// Verifies signature for given ```Collection``` struct
    ///
    /// # Errors
    /// If an error occurs while verifying, ```SignatureError``` is returned
    /// 
    /// If Signature Format is invalid ```SignatureError::InvalidSignature``` is returned
    /// 
    /// If Signature does not match ```SignatureError::VerificationError``` is returned
    /// 
    async fn verify(&self, collection: &Collection) -> Result<(), SignatureError>;
}

#[derive(Debug)]
pub enum SignatureError {
    InvalidSignature { name: String },
    VerificationError { name: String },
}

impl From<ReqwestError> for SignatureError {
    fn from(err: ReqwestError) -> Self {
        err.into()
    }
}

impl From<signatory::error::Error> for SignatureError {
    fn from(err: signatory::error::Error) -> Self {
        SignatureError::VerificationError {
            name: err.to_string(),
        }
    }
}

impl From<openssl::error::ErrorStack> for SignatureError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        err.into()
    }
}

impl From<base64::DecodeError> for SignatureError {
    fn from(err: base64::DecodeError) -> Self {
        SignatureError::InvalidSignature {
            name: err.to_string(),
        }
    }
}

pub struct DefaultVerifier {}

#[async_trait]
impl Verification for DefaultVerifier {
    async fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
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