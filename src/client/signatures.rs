use crate::client::Collection;

use async_trait::async_trait;
use reqwest::Error as ReqwestError;

#[async_trait]
pub trait Verification {
    async fn verify(collection: &Collection) -> Result<(), SignatureError>;
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
