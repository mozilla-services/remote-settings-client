/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::client::Collection;
use canonical_json::CanonicalJSONError;

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

impl From<base64::DecodeError> for SignatureError {
    fn from(err: base64::DecodeError) -> Self {
        SignatureError::InvalidSignature {
            name: err.to_string(),
        }
    }
}

impl From<CanonicalJSONError> for SignatureError {
    fn from(err: CanonicalJSONError) -> Self {
        err.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{Collection, Verification};
    use env_logger;
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use serde_json::json;

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
                match verifier.verify(&collection) {
                    Err(err) => {
                        println!("{:?}", err);
                        assert!(false)
                    }
                    Ok(_) => println!("success"),
                }
            }
        }

        assert_eq!(verifiers.len(), get_pem_certificate.times_called());
        get_pem_certificate.delete();
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_verify_signature() {
        init();

        let mock_server: MockServer = MockServer::start();

        const VALID_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
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

        const INVALID_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
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
                records: Vec::new(),
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
                records: vec![json!("record1")],
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
                records: Vec::new(),
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
                records: Vec::new(),
            },
            INVALID_CERTIFICATE,
            true,
        );
    }
}
