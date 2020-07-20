use crate::client::Collection;

use base64;
use canonical_json::ser::{to_string, CanonicalJSONError};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde_json::json;
use signatory::{
    ecdsa::{curve::NistP384, FixedSignature},
    verify_sha384, EcdsaPublicKey, Signature,
};
use signatory_ring::ecdsa::P384Verifier;
use url::{ParseError, Url};
use viaduct::{Error as ViaductError, Request};

/// A trait for giving a type a custom signature verifier
///
/// Sometimes, you want to use your own verification implementation to verify signature retrieved from the remote-settings server
///
/// # How can I implement ```Verification```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::client::Collection;
/// struct SignatureVerifier {}
///
/// impl Verification for SignatureVerifier {
///     fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
///         Ok(())
///     }
/// }
/// ```
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
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError>;
}

#[derive(Debug)]
pub enum SignatureError {
    InvalidSignature { name: String },
    VerificationError { name: String },
}

impl From<ViaductError> for SignatureError {
    fn from(err: ViaductError) -> Self {
        err.into()
    }
}

impl From<ParseError> for SignatureError {
    fn from(err: ParseError) -> Self {
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

impl From<CanonicalJSONError> for SignatureError {
    fn from(err: CanonicalJSONError) -> Self {
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

impl Verification for DefaultVerifier {
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
        // Fetch certificate PEM (public key).
<<<<<<< HEAD
        let x5u = match collection.metadata["signature"]["x5u"].as_str() {
            Some(x5u) => x5u,
            None => {
                return Err(SignatureError::InvalidSignature {
                    name: "x5u field not present in signature".to_owned(),
                });
            }
        };
=======
        let x5u = collection.metadata["signature"]["x5u"].as_str().ok_or_else(
            || SignatureError::InvalidSignature {
                name: "x5u field not present in signature".to_owned()
               }
        )?;
>>>>>>> Introduce Viaduct, synchronous API

        let resp = Request::get(Url::parse(&x5u)?).send()?;
        let pem = resp.body;

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
        let b64_signature = match collection.metadata["signature"]["signature"].as_str() {
            Some(b64_signature) => b64_signature,
            None => "",
        };

        let signature_bytes = base64::decode_config(&b64_signature, base64::URL_SAFE)?;
        let signature = FixedSignature::<NistP384>::from_bytes(&signature_bytes)?;

        // Serialized data.
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by(|a, b| (a["id"]).to_string().cmp(&b["id"].to_string()));
        let serialized = to_string(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string().to_owned()
        }))?;

        let data = format!("Content-Signature:\x00{}", serialized);

        // Verify
        verify_sha384(&P384Verifier::from(&pk), &data.as_bytes(), &signature)?;

        Ok(())
    }
}
