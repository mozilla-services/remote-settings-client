/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::x509;
use super::{Collection, SignatureError, Verification};
use log::debug;
use ring::digest::{Context, SHA256};
use ring::signature;

use oid_registry;
use x509_parser::time::ASN1Time;

macro_rules! hex {
    ($b: expr) => {{
        let ss: Vec<String> = $b.iter().map(|b| format!("{:02X}", b)).collect();
        ss.join(":")
    }};
}

pub struct RingVerifier {}

impl RingVerifier {}

impl Verification for RingVerifier {
    fn verify(&self, collection: &Collection, root_hash: &str) -> Result<(), SignatureError> {
        debug!("Verifying using x509-parser and ring");

        // Get public key from certificate (PEM from `x5u` field).
        // TODO: read server time from headers to compute clock skew
        let pem_bytes = self.fetch_certificate_chain(&collection)?;

        let pems = x509::parse_certificate_chain(&pem_bytes)?;

        let certs: Vec<x509::X509Certificate> = pems
            .iter()
            .map(|pem| match x509::parse_x509_certificate(&pem) {
                Ok(cert) => Ok(cert),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<x509::X509Certificate>, _>>()?;

        let root_pem = pems.first().unwrap();

        // Verify root hash: hex fingerprint of DER content.
        let mut context = Context::new(&SHA256);
        context.update(&root_pem.contents);
        let root_fingerprint = hex!(context.finish().as_ref());
        if root_fingerprint != root_hash {
            return Err(SignatureError::CertificateHasWrongRoot(root_fingerprint));
        }

        let leaf_cert = certs.last().unwrap(); // PEM parse fails if len == 0.

        // Check certificate validity.
        // TODO: take clock skew into account
        // TODO: mock from tests
        let now = ASN1Time::now();
        if !leaf_cert.tbs_certificate.validity.is_valid_at(now) {
            return Err(SignatureError::CertificateExpired);
        }

        // Verify signature chain.
        for pair in certs.windows(2) {
            if let [parent, child] = pair {
                let signature_alg = &child.signature_algorithm.algorithm;
                let verification_alg: &dyn signature::VerificationAlgorithm =
                    if *signature_alg == oid_registry::OID_PKCS1_SHA1WITHRSA {
                        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                    } else if *signature_alg == oid_registry::OID_PKCS1_SHA256WITHRSA {
                        &signature::RSA_PKCS1_2048_8192_SHA256
                    } else if *signature_alg == oid_registry::OID_PKCS1_SHA384WITHRSA {
                        &signature::RSA_PKCS1_2048_8192_SHA384
                    } else if *signature_alg == oid_registry::OID_PKCS1_SHA512WITHRSA {
                        &signature::RSA_PKCS1_2048_8192_SHA512
                    } else if *signature_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
                        &signature::ECDSA_P256_SHA256_ASN1
                    } else if *signature_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
                        &signature::ECDSA_P384_SHA384_ASN1
                    } else {
                        return Err(SignatureError::UnsupportedSignatureAlgorithm);
                    };
                let parent_pk_bytes = parent.tbs_certificate.subject_pki.subject_public_key.data;
                let parent_pk = signature::UnparsedPublicKey::new(verification_alg, &parent_pk_bytes);
                let child_sig_bytes = child.signature_value.data;
                parent_pk.verify(child.tbs_certificate.as_ref(), child_sig_bytes)
                    .or(Err(SignatureError::CertificateTrustError))?;
            }
        }

        // Extract SubjectPublicKeyInfo of leaf certificate.
        let public_key_bytes = leaf_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            &public_key_bytes,
        );

        let signature_bytes = self.decode_signature(&collection)?;

        let data_bytes = self.serialize_data(&collection)?;

        // Verify data against signature using public key
        match public_key.verify(&data_bytes, &signature_bytes) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::MismatchError(err.to_string())),
        }
    }
}
