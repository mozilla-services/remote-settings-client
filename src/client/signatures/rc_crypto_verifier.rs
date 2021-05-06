/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{x509, SignatureError, Verification};
use rc_crypto::digest::{digest, SHA256};
use rc_crypto::signature;
use x509_parser::time::ASN1Time;

pub struct RcCryptoVerifier {}

impl RcCryptoVerifier {}

impl Verification for RcCryptoVerifier {
    fn verify_nist384p_chain(
        &self,
        epoch_seconds: u64,
        pem_bytes: &[u8],
        root_hash: &[u8],
        subject_cn: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        // WARNING
        //
        // This code is a duplication of the ring_verifier code
        // and is not meant to be used in production.
        //
        // Until the equivalent becomes available in NSS, this was
        // implemented only to make tests pass.
        // See https://github.com/mozilla-services/remote-settings-client/issues/98
        //
        // rc_crypto::verify_nist384p_chain(...)
        //
        let pems = x509::parse_certificate_chain(&pem_bytes)?;
        let certs: Vec<x509::X509Certificate> = pems
            .iter()
            .map(|pem| match x509::parse_x509_certificate(&pem) {
                Ok(cert) => Ok(cert),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<x509::X509Certificate>, _>>()?;
        let root_pem = pems.first().unwrap();
        let root_fingerprint_bytes = match digest(&SHA256, &root_pem.contents) {
            Ok(v) => v.as_ref().to_vec(),
            Err(e) => {
                return Err(SignatureError::HashingError(e.to_string()));
            }
        };
        if root_fingerprint_bytes != root_hash {
            return Err(SignatureError::CertificateHasWrongRoot(hex::encode(
                root_fingerprint_bytes,
            )));
        }
        let now = ASN1Time::from_timestamp(epoch_seconds as i64);
        for cert in &certs {
            if !cert.tbs_certificate.validity.is_valid_at(now) {
                return Err(SignatureError::CertificateExpired);
            }
        }
        let leaf_cert = certs.last().unwrap(); // PEM parse fails if len == 0.
        let leaf_subject = leaf_cert
            .tbs_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("")
            .to_string();
        if leaf_subject != subject_cn {
            return Err(SignatureError::WrongSignerName(leaf_subject));
        }
        let public_key_bytes = leaf_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let signature_alg = &signature::ECDSA_P384_SHA384;
        let public_key = signature::UnparsedPublicKey::new(signature_alg, &public_key_bytes);
        match public_key.verify(&message, &signature) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::MismatchError(err.to_string())),
        }
    }
}
