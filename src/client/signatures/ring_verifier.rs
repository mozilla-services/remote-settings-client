/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{HashAlgorithm, SignatureError, Verification, VerificationAlgorithm};
use ring::digest::{Context, SHA256};
use ring::signature;

pub struct RingVerifier {}

impl RingVerifier {}

impl Verification for RingVerifier {
    fn hash(&self, input: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, SignatureError> {
        let hash_alg = match algorithm {
            HashAlgorithm::SHA256 => &SHA256,
        };
        let mut context = Context::new(hash_alg);
        context.update(input);
        Ok(context.finish().as_ref().to_vec())
    }

    fn verify_message(
        &self,
        message: &[u8],
        key: &[u8],
        signature: &[u8],
        algorithm: VerificationAlgorithm,
    ) -> Result<(), SignatureError> {
        let signature_alg: &dyn signature::VerificationAlgorithm = match algorithm {
            VerificationAlgorithm::RSA_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            VerificationAlgorithm::RSA_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            VerificationAlgorithm::RSA_SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            VerificationAlgorithm::ECDSA_P256_SHA256_ASN1 => &signature::ECDSA_P256_SHA256_ASN1,
            VerificationAlgorithm::ECDSA_P384_SHA384_ASN1 => &signature::ECDSA_P384_SHA384_ASN1,
            VerificationAlgorithm::ECDSA_P256_SHA256_FIXED => &signature::ECDSA_P256_SHA256_FIXED,
            VerificationAlgorithm::ECDSA_P384_SHA384_FIXED => &signature::ECDSA_P384_SHA384_FIXED,
        };
        let public_key = signature::UnparsedPublicKey::new(signature_alg, &key);
        match public_key.verify(&message, &signature) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::MismatchError(err.to_string())),
        }
    }
}
