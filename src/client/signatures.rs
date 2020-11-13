/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::client::Collection;
use base64;
use url::ParseError;
use viaduct::Error as ViaductError;
#[cfg(not(feature = "openssl_verifier"))]
pub mod default_verifier;
#[cfg(feature = "openssl_verifier")]
pub mod openssl_verifier;
use log::debug;

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

#[derive(Debug, PartialEq)]
pub enum SignatureError {
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
