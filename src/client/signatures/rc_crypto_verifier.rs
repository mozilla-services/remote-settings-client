/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{x509, HashAlgorithm, SignatureError, Verification, VerificationAlgorithm};
use rc_crypto::signature;
use rc_crypto::digest::{digest, SHA256};

pub struct RcCryptoVerifier {}

impl RcCryptoVerifier {}

impl Verification for RcCryptoVerifier {
    fn hash(&self, input: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, SignatureError> {
        let hash_alg = match algorithm {
            HashAlgorithm::SHA256 => &SHA256,
        };
        match digest(hash_alg, &input) {
            Ok(v) => Ok(v.as_ref().to_vec()),
            Err(e) => Err(SignatureError::HashingError(e.to_string()))
        }
    }

    fn verify_chain(&self, _: Vec<&x509::X509Certificate>) -> Result<(), SignatureError> {
        // rc_crypto lacks RSA support.
        Ok(())
    }

    fn verify_message(
        &self,
        message: &[u8],
        key: &[u8],
        signature: &[u8],
        algorithm: VerificationAlgorithm,
    ) -> Result<(), SignatureError> {
        let signature_alg = match algorithm {
            VerificationAlgorithm::ECDSA_P384_SHA384_FIXED => &signature::ECDSA_P384_SHA384,
            VerificationAlgorithm::ECDSA_P256_SHA256_FIXED => &signature::ECDSA_P256_SHA256,
            _ => return Err(SignatureError::UnsupportedSignatureAlgorithm),
        };
        let public_key = signature::UnparsedPublicKey::new(signature_alg, &key);
        match public_key.verify(&message, &signature) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::MismatchError(err.to_string())),
        }
    }
}
