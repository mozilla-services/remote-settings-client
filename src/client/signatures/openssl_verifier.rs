/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "openssl_verifier")]
use {
    super::{Collection, SignatureError, Verification},
    canonical_json::{to_string, CanonicalJSONError},
    log::debug,
    openssl::bn::BigNumContext,
    openssl::ec::{EcGroup, PointConversionForm},
    openssl::nid::Nid,
    openssl::x509::X509,
    serde_json::json,
    signatory::{
        ecdsa::{curve::NistP384, FixedSignature},
        verify_sha384, EcdsaPublicKey, Signature,
    },
    signatory_ring::ecdsa::P384Verifier,
    url::Url,
    viaduct::Request,
};

pub struct OpenSSLVerifier {}

impl OpenSSLVerifier {
    fn fetch_certificate(&self, collection: &Collection) -> Result<X509, SignatureError> {
        // Fetch certificate PEM (public key).
        let x5u = collection.metadata["signature"]["x5u"]
            .as_str()
            .ok_or_else(|| SignatureError::InvalidSignature {
                name: "x5u field not present in signature".to_owned(),
            })?;

        debug!("Fetching certificate {}", x5u);
        let resp = Request::get(Url::parse(&x5u)?).send()?;

        // Parse PEM (OpenSSL)
        let cert: X509 = match X509::from_pem(&resp.body) {
            Ok(certificate) => certificate,
            Err(err) => {
                debug!("Encountered an error {}", err);
                return Err(SignatureError::InvalidSignature {
                    name: err.to_string(),
                });
            }
        };

        Ok(cert)
    }

    fn get_public_key(
        &self,
        certificate: X509,
    ) -> Result<EcdsaPublicKey<NistP384>, SignatureError> {
        let public_key = certificate.public_key()?;
        let ec_public_key = public_key.ec_key()?;
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let public_key_bytes = ec_public_key.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;
        let pk: EcdsaPublicKey<NistP384> = EcdsaPublicKey::from_bytes(&public_key_bytes)?;

        Ok(pk)
    }

    fn extract_signature(
        &self,
        collection: &Collection,
    ) -> Result<FixedSignature<NistP384>, SignatureError> {
        let b64_signature = match collection.metadata["signature"]["signature"].as_str() {
            Some(b64_signature) => b64_signature,
            None => "",
        };

        let signature_bytes = base64::decode_config(&b64_signature, base64::URL_SAFE)?;
        let signature = FixedSignature::<NistP384>::from_bytes(&signature_bytes)?;

        Ok(signature)
    }
}

#[cfg(feature = "openssl_verifier")]
impl From<signatory::error::Error> for SignatureError {
    fn from(err: signatory::error::Error) -> Self {
        SignatureError::VerificationError {
            name: err.to_string(),
        }
    }
}

#[cfg(feature = "openssl_verifier")]
impl From<openssl::error::ErrorStack> for SignatureError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        err.into()
    }
}

#[cfg(feature = "openssl_verifier")]
impl From<CanonicalJSONError> for SignatureError {
    fn from(err: CanonicalJSONError) -> Self {
        err.into()
    }
}

#[cfg(feature = "openssl_verifier")]
impl Verification for OpenSSLVerifier {
    fn verify(&self, collection: &Collection) -> Result<(), SignatureError> {
        debug!("Verifying using OpenSSL");

        let certificate = self.fetch_certificate(collection)?;

        // Get public key from certificate
        let public_key = self.get_public_key(certificate)?;

        // Instantiate signature
        let signature = self.extract_signature(collection)?;

        // Serialized data.
        let mut sorted_records = collection.records.to_vec();
        sorted_records.sort_by(|a, b| (a["id"]).to_string().cmp(&b["id"].to_string()));
        let serialized = to_string(&json!({
            "data": sorted_records,
            "last_modified": collection.timestamp.to_string().to_owned()
        }))?;

        let data = format!("Content-Signature:\x00{}", serialized);

        // Verify
        verify_sha384(
            &P384Verifier::from(&public_key),
            &data.as_bytes(),
            &signature,
        )?;

        debug!("Done verifying signature");
        Ok(())
    }
}

#[cfg(feature = "openssl_verifier")]
#[cfg(test)]
mod tests {
    use super::{Collection, OpenSSLVerifier, SignatureError, Verification};
    use env_logger;
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use log::debug;
    use serde_json::json;
    use url::{ParseError, Url};
    use viaduct::{set_backend, Error as ViaductError, Request};
    use viaduct_reqwest::ReqwestBackend;

    fn openssl_verify(
        mock_server: &MockServer,
        collection: Collection,
        certificate: &str,
        should_fail: bool,
    ) {
        let openssl_verifier = OpenSSLVerifier {};

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
            assert!(openssl_verifier.verify(&collection).is_err())
        } else {
            assert!(openssl_verifier.verify(&collection).is_ok())
        }

        assert_eq!(1, get_pem_certificate.times_called());
        get_pem_certificate.delete();
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        set_backend(&ReqwestBackend).unwrap();
    }

    #[test]
    fn test_openssl_verify() {
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

        openssl_verify(
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
        openssl_verify(
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
        openssl_verify(
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
        openssl_verify(
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
