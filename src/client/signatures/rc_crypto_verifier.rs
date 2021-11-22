/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{SignatureError, Verification};
use async_trait::async_trait;
use rc_crypto::{contentsignature, ErrorKind as RcErrorKind, digest};

pub struct RcCryptoVerifier {}

impl RcCryptoVerifier {}

#[async_trait]
impl Verification for RcCryptoVerifier {
    fn verify_nist384p_chain(
        &self,
        epoch_seconds: u64,
        pem_bytes: &[u8],
        root_hash: &str,
        subject_cn: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        contentsignature::verify(
            message,
            signature,
            pem_bytes,
            epoch_seconds,
            root_hash,
            subject_cn,
        )?;
        Ok(())
    }

    fn verify_sha256_hash(&self, content: &[u8], expected: &[u8]) -> Result<(), SignatureError> {
        let hash = digest::digest(&digest::SHA256, content)?;
        if hash.as_ref() == expected {
            Ok(())
        } else {
            Err(SignatureError::MismatchError("content did not match expected sha256 hash".to_string()))
        }
    }
}

impl From<rc_crypto::Error> for SignatureError {
    fn from(err: rc_crypto::Error) -> Self {
        match err.kind() {
            RcErrorKind::RootHashFormatError(detail) => {
                SignatureError::RootHashFormatError(detail.to_string())
            }
            RcErrorKind::PEMFormatError(detail) => {
                SignatureError::CertificateContentError(detail.to_string())
            }
            RcErrorKind::CertificateContentError(detail) => {
                SignatureError::CertificateContentError(detail.to_string())
            }
            RcErrorKind::SignatureContentError(detail) => {
                SignatureError::BadSignatureContent(detail.to_string())
            }
            RcErrorKind::CertificateSubjectError => {
                SignatureError::InvalidCertificateSubject("".to_string())
            }
            RcErrorKind::CertificateIssuerError => {
                SignatureError::InvalidCertificateIssuer("".to_string())
            }
            RcErrorKind::CertificateValidityError => SignatureError::CertificateExpired,
            RcErrorKind::CertificateChainError(_) => SignatureError::CertificateTrustError,
            _ => SignatureError::MismatchError(err.to_string()),
        }
    }
}
