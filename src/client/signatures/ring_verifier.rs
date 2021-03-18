/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use {
    super::x509,
    super::{Collection, SignatureError, Verification},
    log::debug,
    ring::signature,
};

pub struct RingVerifier {}

impl RingVerifier {}

impl Verification for RingVerifier {
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
        debug!("Verifying using x509-parser and ring");

        // Get public key from certificate (PEM from `x5u` field).
        let pem_bytes = self.fetch_certificate_chain(&collection)?;

        let public_key_bytes = x509::extract_public_key(pem_bytes)?;
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            &public_key_bytes,
        );

        let signature_bytes = self.decode_signature(&collection)?;

        let data_bytes = self.serialize_data(&collection)?;

        // Verify data against signature using public key
        match public_key.verify(&data_bytes, &signature_bytes) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::VerificationError {
                name: err.to_string(),
            }),
        }
    }
}
