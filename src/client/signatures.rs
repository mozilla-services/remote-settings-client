/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::client::Collection;
use canonical_json::CanonicalJSONError;
use url::ParseError;
use viaduct::Error as ViaductError;

pub mod default_verifier;
#[cfg(feature = "ring_verifier")]
pub mod ring_verifier;

use log::debug;

/// A trait for signature verification of collection data.
///
/// You may want to use your own verification implementation (eg. using OpenSSL instead of `ring` or `rc_crypto`).
///
/// # How can I implement ```Verification```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification};
/// # use remote_settings_client::{Client, Collection};
///
/// struct SignatureVerifier {}
///
/// impl Verification for SignatureVerifier {
///     fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
///         Ok(())
///     }
/// }
///
/// # fn main() {
/// let client = Client::builder()
///    .collection_name("cid")
///    .verifier(Box::new(SignatureVerifier {}))
///    .build();
/// # }
/// ```
pub trait Verification {
    /// Verifies signature for a given ```Collection``` struct
    ///
    /// # Errors
    /// If an error occurs while verifying, ```SignatureError``` is returned
    ///
    /// If the signature format or content is invalid, ```SignatureError::InvalidSignature``` is returned
    ///
    /// If the signature does not match the content, ```SignatureError::VerificationError``` is returned
    ///
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError>;
}

#[derive(Debug, PartialEq)]
pub enum SignatureError {
    CertificateError { name: String },
    InvalidSignature { name: String },
    VerificationError { name: String },
}

impl From<ViaductError> for SignatureError {
    fn from(err: ViaductError) -> Self {
        debug!("viaduct error here {}", err);
        err.into()
    }
}

impl From<ParseError> for SignatureError {
    fn from(err: ParseError) -> Self {
        debug!("parse error here {}", err);
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

impl From<CanonicalJSONError> for SignatureError {
    fn from(err: CanonicalJSONError) -> Self {
        err.into()
    }
}
