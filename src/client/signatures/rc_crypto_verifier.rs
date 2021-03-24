/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::x509;
use super::{Collection, SignatureError, Verification};
use log::debug;
use rc_crypto::signature;

pub struct RcCryptoVerifier {}

impl RcCryptoVerifier {}

impl Verification for RcCryptoVerifier {
    fn verify(&self, collection: &Collection, root_hash: &str) -> Result<(), SignatureError> {
        debug!("Verifying using x509-parser and rc_crypto");

        // Get public key from certificate (PEM from `x5u` field).
        let pem_bytes = self.fetch_certificate_chain(&collection)?;

        let pems = x509::parse_certificate_chain(&pem_bytes)?;

        let certs: Vec<x509::X509Certificate> = pems
            .iter()
            .map(|pem| match x509::parse_x509_certificate(&pem) {
                Ok(cert) => Ok(cert),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<x509::X509Certificate>, _>>()?;

        // Extract SubjectPublicKeyInfo of leaf certificate.
        let leaf_cert = certs.first().unwrap(); // PEM parse fails if len == 0.
        let public_key_bytes = leaf_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384, &public_key_bytes);

        let signature_bytes = self.decode_signature(&collection)?;

        let data_bytes = self.serialize_data(&collection)?;

        // Verify data against signature using public key
        match public_key.verify(&data_bytes, &signature_bytes) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::MismatchError(err.to_string())),
        }
    }
}
