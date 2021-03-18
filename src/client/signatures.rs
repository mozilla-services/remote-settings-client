/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use {
    crate::client::Collection, canonical_json, log::debug, serde_json::json, url::ParseError,
    url::Url, viaduct::Error as ViaductError, viaduct::Request,
};

pub mod dummy_verifier;

#[cfg(feature = "ring_verifier")]
pub mod ring_verifier;

#[cfg(feature = "rc_crypto_verifier")]
pub mod rc_crypto_verifier;

#[cfg(any(feature = "ring_verifier", feature = "rc_crypto_verifier"))]
pub mod x509;

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
    fn fetch_certificate_chain(&self, collection: &Collection) -> Result<Vec<u8>, SignatureError> {
        // Fetch certificate PEM (public key).
        let x5u = collection.metadata["signature"]["x5u"].as_str().ok_or(
            SignatureError::InvalidSignature {
                name: "x5u field not present in signature".to_owned(),
            },
        )?;

        debug!("Fetching certificate {}", x5u);
        let resp = Request::get(Url::parse(&x5u)?).send()?;
        if !resp.is_success() {
            return Err(SignatureError::CertificateError {
                name: format!("PEM could not be downloaded (HTTP {})", resp.status),
            });
        }

        Ok(resp.body)
    }

    fn decode_signature(&self, collection: &Collection) -> Result<Vec<u8>, SignatureError> {
        let b64_signature = collection.metadata["signature"]["signature"]
            .as_str()
            .unwrap_or("");

        Ok(base64::decode_config(&b64_signature, base64::URL_SAFE)?)
    }

    fn serialize_data(&self, collection: &Collection) -> Result<Vec<u8>, SignatureError> {
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by_cached_key(|r| r.id().to_owned());
        let serialized = canonical_json::to_string(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string()
        }))?;
        let data = format!("Content-Signature:\x00{}", serialized);

        Ok(data.as_bytes().to_vec())
    }

    /// Verifies signature for a given ```Collection``` struct
    ///
    /// # Errors
    /// If an error occurs while verifying, ```SignatureError``` is returned
    ///
    /// If the error is related to the certificate, ```SignatureError::CertificateError``` is returned
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
        SignatureError::CertificateError {
            name: err.to_string(),
        }
    }
}

impl From<ParseError> for SignatureError {
    fn from(err: ParseError) -> Self {
        SignatureError::CertificateError {
            name: err.to_string(),
        }
    }
}

impl From<base64::DecodeError> for SignatureError {
    fn from(err: base64::DecodeError) -> Self {
        SignatureError::InvalidSignature {
            name: err.to_string(),
        }
    }
}

impl From<canonical_json::CanonicalJSONError> for SignatureError {
    fn from(err: canonical_json::CanonicalJSONError) -> Self {
        err.into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Collection, Record, SignatureError, Verification};
    use env_logger;
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use serde_json::json;
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;

    struct BasicVerifier {}

    impl Verification for BasicVerifier {
        fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    fn verify_signature(
        mock_server: &MockServer,
        collection: Collection,
        certificate: &str,
        should_fail: bool,
    ) {
        let mut get_pem_certificate = Mock::new()
            .expect_method(GET)
            .expect_path(
                "/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain",
            )
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(certificate)
            .create_on(&mock_server);

        let mut verifiers: Vec<Box<dyn Verification>> = Vec::new();

        #[cfg(feature = "ring_verifier")]
        verifiers.push(Box::new(super::ring_verifier::RingVerifier {}));

        #[cfg(feature = "rc_crypto_verifier")]
        verifiers.push(Box::new(super::rc_crypto_verifier::RcCryptoVerifier {}));

        for verifier in &verifiers {
            if should_fail {
                assert!(verifier.verify(&collection).is_err())
            } else {
                assert!(verifier.verify(&collection).is_ok());
            }
        }

        assert_eq!(verifiers.len(), get_pem_certificate.times_called());
        get_pem_certificate.delete();
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_missing_x5u() {
        let verifier = BasicVerifier {};
        let collection = Collection {
            bid: "".to_string(),
            cid: "".to_string(),
            metadata: json!({}),
            records: vec![],
            timestamp: 0,
        };
        let err = verifier.fetch_certificate_chain(&collection).unwrap_err();
        match err {
            SignatureError::InvalidSignature { name } => {
                assert_eq!(name, "x5u field not present in signature")
            }
            e => assert!(false, format!("Unexpected error type: {:?}", e)),
        };
    }

    #[test]
    fn test_bad_x5u_urls() {
        let verifier = BasicVerifier {};

        let _ = set_backend(&ReqwestBackend);
        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("/file.pem");
        let mut pem_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/file.pem")
            .return_status(404)
            .create_on(&mock_server);

        let expectations: Vec<(&str, &str)> = vec![
            ("%^", "relative URL without a base"),
            (
                "http://localhost:9999/bad",
                "Network error: error sending request",
            ),
            (
                &mock_server_address,
                "PEM could not be downloaded (HTTP 404)",
            ),
        ];

        for (url, error) in expectations {
            let collection = Collection {
                bid: "".to_string(),
                cid: "".to_string(),
                metadata: json!({
                    "signature": {
                        "x5u": url
                    }
                }),
                records: vec![],
                timestamp: 0,
            };
            let err = verifier.fetch_certificate_chain(&collection).unwrap_err();
            match err {
                SignatureError::CertificateError { name } => {
                    assert!(name.contains(error))
                }
                e => assert!(false, format!("Unexpected error type: {:?}", e)),
            };
        }

        pem_mock.delete();
    }

    #[test]
    fn test_verify_signature() {
        init();

        let mock_server: MockServer = MockServer::start();

        const VALID_CERTIFICATE: &str = r#"\
-----BEGIN CERTIFICATE-----
MIIDBjCCAougAwIBAgIIFiJLFfdxFlYwCgYIKoZIzj0EAwMwgaMxCzAJBgNVBAYT
AlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3pp
bGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTFFMEMGA1UEAww8Q29u
dGVudCBTaWduaW5nIEludGVybWVkaWF0ZS9lbWFpbEFkZHJlc3M9Zm94c2VjQG1v
emlsbGEuY29tMB4XDTIwMDYxNjE3MTYxNVoXDTIwMDkwNDE3MTYxNVowgakxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFp
biBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcwFQYDVQQLEw5D
bG91ZCBTZXJ2aWNlczE2MDQGA1UEAxMtcmVtb3RlLXNldHRpbmdzLmNvbnRlbnQt
c2lnbmF0dXJlLm1vemlsbGEub3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDmOX
N5IGlUqCvu6xkOKr020Eo3kY2uPdJO0ZihVUoglk1ktQPss184OajFOMKm/BJX4W
IsZUzQoRL8NgGfZDwBjT95Q87lhOWEWs5AU/nMXIYwDp7rpUPaUqw0QLMikdo4GD
MIGAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSME
GDAWgBSgHUoXT4zCKzVF8WPx2nBwp8744TA4BgNVHREEMTAvgi1yZW1vdGUtc2V0
dGluZ3MuY29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMD
aQAwZgIxAJvyynyPqRmRMqf95FPH5xfcoT3jb/2LOkUifGDtjtZ338ScpT2glUK8
HszKVANqXQIxAIygMaeTiD9figEusmHMthBdFoIoHk31x4MHukAy+TWZ863X6/V2
6/ZrZMp6Wq/0ow==
-----END CERTIFICATE-----"#;

        const INVALID_CERTIFICATE: &str = r#"\
-----BEGIN CERTIFICATE-----
invalidCertificategIFiJLFfdxFlYwCgYIKoZIzj0EAwMwgaMxCzAJBgNVBAYT
AlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3pp
bGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTFFMEMGA1UEAww8Q29u
dGVudCBTaWduaW5nIEludGVybWVkaWF0ZS9lbWFpbEFkZHJlc3M9Zm94c2VjQG1v
emlsbGEuY29tMB4XDTIwMDYxNjE3MTYxNVoXDTIwMDkwNDE3MTYxNVowgakxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFp
biBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcwFQYDVQQLEw5D
bG91ZCBTZXJ2aWNlczE2MDQGA1UEAxMtcmVtb3RlLXNldHRpbmdzLmNvbnRlbnQt
c2lnbmF0dXJlLm1vemlsbGEub3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDmOX
N5IGlUqCvu6xkOKr020Eo3kY2uPdJO0ZihVUoglk1ktQPss184OajFOMKm/BJX4W
IsZUzQoRL8NgGfZDwBjT95Q87lhOWEWs5AU/nMXIYwDp7rpUPaUqw0QLMikdo4GD
MIGAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSME
GDAWgBSgHUoXT4zCKzVF8WPx2nBwp8744TA4BgNVHREEMTAvgi1yZW1vdGUtc2V0
dGluZ3MuY29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMD
aQAwZgIxAJvyynyPqRmRMqf95FPH5xfcoT3jb/2LOkUifGDtjtZ338ScpT2glUK8
HszKVANqXQIxAIygMaeTiD9figEusmHMthBdFoIoHk31x4MHukAy+TWZ863X6/V2
6/ZrZMpinvalid==
-----END CERTIFICATE-----"#;

        const VALID_SIGNATURE: &str = r#"oPRadsg_5wnnUXlRIjamXKPWyyGe4VLt-KR4-PJTK2hq4hF196L3nbvne1_7-HfpoVRR4BLsHWtnnt6700CTt5kNgwvrE8aJ3nXFa0vJBoOvIRco-vCt-rJ7acEu0IFG"#;

        const INVALID_SIGNATURE: &str = r#"invalid-signature: oPRadsg_5wnnUXlRIjamXKPWyyGe4VLt-KR4-PJTK2hq4hF196L3nbvne1_7-HfpoVRR4BLsHWtnnt6700CTt5kNgwvrE8aJ3nXFa0vJBoOvIRco-vCt-rJ7acEu0IFG"#;

        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": format!("{}/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain", mock_server.url("")),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![],
            },
            VALID_CERTIFICATE,
            false,
        );

        // signature verification should fail with invalid message
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": format!("{}/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain", mock_server.url("")),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![Record::new(json!({"id": "bad-record"}))],
            },
            VALID_CERTIFICATE,
            true,
        );

        // signature verification should fail with invalid signature
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": format!("{}/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain", mock_server.url("")),
                        "signature": INVALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![],
            },
            VALID_CERTIFICATE,
            true,
        );

        // signature verification should fail with invalid certificate
        verify_signature(
            &mock_server,
            Collection {
                bid: "main".to_owned(),
                cid: "pioneer-study-addons".to_owned(),
                metadata: json!({
                    "signature": json!({
                        "x5u": format!("{}/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain", mock_server.url("")),
                        "signature": VALID_SIGNATURE
                    })
                }),
                timestamp: 1594998798350,
                records: vec![],
            },
            INVALID_CERTIFICATE,
            true,
        );
    }
}
