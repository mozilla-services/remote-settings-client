/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use {
    super::x509::fetch_public_key,
    super::{Collection, SignatureError, Verification},
    canonical_json,
    log::debug,
    rc_crypto::signature,
    serde_json::json,
};

pub struct RcCryptoVerifier {}

impl RcCryptoVerifier {}

impl Verification for RcCryptoVerifier {
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
        debug!("Verifying using x509-parser and rc_crypto");

        // Fetch certificate PEM (public key).
        let x5u = collection.metadata["signature"]["x5u"].as_str().ok_or(
            SignatureError::InvalidSignature {
                name: "x5u field not present in signature".to_owned(),
            },
        )?;

        let public_key_bytes = fetch_public_key(&x5u)?;

        // Get public key from certificates
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384, &public_key_bytes);

        // Instantiate signature
        let b64_signature = collection.metadata["signature"]["signature"]
            .as_str()
            .unwrap_or("");
        let signature_bytes = base64::decode_config(&b64_signature, base64::URL_SAFE)?;

        // Serialized data.
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by_cached_key(|a| a["id"].as_str().unwrap().to_owned());
        let serialized = canonical_json::to_string(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string()
        }))?;

        let data = format!("Content-Signature:\x00{}", serialized);

        // Verify data against signature using public key
        match public_key.verify(&data.as_bytes(), &signature_bytes) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::VerificationError {
                name: err.to_string(),
            }),
        }
    }
}
