/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "ring_verifier")]
use {
    super::{Collection, SignatureError, Verification},
    canonical_json::to_string,
    log::debug,
    ring::io::der,
    ring::signature,
    serde_json::json,
    url::Url,
    viaduct::Request,
    x509_parser::{self, error as x509_errors, nom::Err as NomErr},
};

pub struct RingVerifier {}

const SIGNATURE_LENGTH: usize = 96;

#[cfg(feature = "ring_verifier")]
impl From<NomErr<x509_errors::X509Error>> for SignatureError {
    fn from(err: NomErr<x509_errors::X509Error>) -> Self {
        SignatureError::CertificateError {
            name: err.to_string(),
        }
    }
}

#[cfg(feature = "ring_verifier")]
impl From<NomErr<x509_errors::PEMError>> for SignatureError {
    fn from(err: NomErr<x509_errors::PEMError>) -> Self {
        SignatureError::CertificateError {
            name: err.to_string(),
        }
    }
}

impl RingVerifier {}

fn encode_dss_signature(signature_bytes: Vec<u8>) -> Vec<u8> {
    // See https://github.com/briansmith/ring/blob/3b1ece4/src/io/der_writer.rs
    let sig_len = signature_bytes.len();
    let r_bytes = &signature_bytes[0..sig_len / 2];
    let s_bytes = &signature_bytes[sig_len / 2..];

    // Encode the two integer points.
    let mut tuple_der: Vec<u8> = Vec::new();
    for val in [r_bytes, s_bytes].iter() {
        tuple_der.push(der::Tag::Integer as u8);
        if (val[0] & 0x80) != 0 {
            // Disambiguate negative number.
            tuple_der.push((val.len() + 1) as u8);
            tuple_der.push(0x00);
        } else {
            tuple_der.push(val.len() as u8);
        }
        tuple_der.extend(*val);
    }

    // Sequence tag followed by content length and bytes.
    let mut signature_der: Vec<u8> = Vec::new();
    signature_der.push(der::Tag::Sequence as u8);
    signature_der.push(tuple_der.len() as u8);
    signature_der.extend(tuple_der);

    signature_der
}

#[cfg(feature = "ring_verifier")]
impl Verification for RingVerifier {
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
        debug!("Verifying using x509-parser and ring");

        // Fetch certificate PEM (public key).
        let x5u = collection.metadata["signature"]["x5u"].as_str().ok_or(
            SignatureError::InvalidSignature {
                name: "x5u field not present in signature".to_owned(),
            },
        )?;

        debug!("Fetching certificate {}", x5u);
        let resp = Request::get(Url::parse(&x5u)?).send()?;

        // Extram PEM.
        // Use this command to debug:
        // ``openssl x509 -inform PEM -in cert.pem -text``
        let pem_bytes = &resp.body;
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem_bytes)?;
        if pem.label != "CERTIFICATE" {
            return Err(SignatureError::CertificateError {
                name: "PEM is not a certificate".to_string(),
            });
        }

        // Extract SubjectPublicKeyInfo
        let (_, x509) = x509_parser::parse_x509_certificate(&pem.contents)?;

        // Get public key from certificate
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            &x509.tbs_certificate.subject_pki.subject_public_key.data,
        );

        // Instantiate signature
        let b64_signature = collection.metadata["signature"]["signature"]
            .as_str()
            .unwrap_or("");
        let signature_bytes = base64::decode_config(&b64_signature, base64::URL_SAFE)?;
        // Signature must be 96 bits.
        if signature_bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError::InvalidSignature {
                name: "Signature has invalid length for NIST P-384 / secp384r1".to_string(),
            });
        };
        // Encode (r, s) in DER format.
        let signature_der = encode_dss_signature(signature_bytes);

        // Serialized data.
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by(|a, b| (a["id"]).to_string().cmp(&b["id"].to_string()));
        let serialized = to_string(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string()
        }))?;

        let data = format!("Content-Signature:\x00{}", serialized);

        // Verify data against signature using public key
        match public_key.verify(&data.as_bytes(), &signature_der) {
            Ok(_) => Ok(()),
            Err(err) => Err(SignatureError::VerificationError {
                name: err.to_string(),
            }),
        }
    }
}

#[cfg(feature = "ring_verifier")]
#[cfg(test)]
mod tests {
    use super::{Collection, RingVerifier, Verification};
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
        let ring_verifier = RingVerifier {};

        let mut get_pem_certificate = Mock::new()
            .expect_method(GET)
            .expect_path(
                "/chains/remote-settings.content-signature.mozilla.org-2020-09-04-17-16-15.chain",
            )
            .return_status(200)
            .return_header("Content-Type", "application/json")
            .return_body(certificate)
            .create_on(&mock_server);

        if should_fail {
            assert!(ring_verifier.verify(&collection).is_err())
        } else {
            match ring_verifier.verify(&collection) {
                Err(err) => {
                    println!("{:?}", err);
                    assert!(false)
                }
                Ok(_) => println!("success"),
            }
        }

        assert_eq!(1, get_pem_certificate.times_called());
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
