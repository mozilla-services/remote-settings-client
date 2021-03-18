/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::SignatureError;
use x509_parser::{self, error as x509_errors, nom::Err as NomErr};

impl From<NomErr<x509_errors::X509Error>> for SignatureError {
    fn from(err: NomErr<x509_errors::X509Error>) -> Self {
        SignatureError::CertificateError {
            name: err.to_string(),
        }
    }
}

impl From<NomErr<x509_errors::PEMError>> for SignatureError {
    fn from(err: NomErr<x509_errors::PEMError>) -> Self {
        SignatureError::CertificateError {
            name: err.to_string(),
        }
    }
}

pub fn extract_public_key(pem_bytes: Vec<u8>) -> Result<Vec<u8>, SignatureError> {
    // ``openssl x509 -inform PEM -in cert.pem -text``
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)?;
    if pem.label != "CERTIFICATE" {
        return Err(SignatureError::CertificateError {
            name: "PEM is not a certificate".to_string(),
        });
    }

    // Extract SubjectPublicKeyInfo
    let (_, x509) = x509_parser::parse_x509_certificate(&pem.contents)?;

    Ok(x509
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::{extract_public_key, SignatureError};

    #[test]
    fn test_bad_pem_content() {
        let expectations: Vec<(&str, &str)> = vec![
            ("%^", "Parsing Error: MissingHeader"),
            (
                "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
bGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTFFMEMGA1UEAww8Q29u
-----END ENCRYPTED PRIVATE KEY-----",
                "PEM is not a certificate",
            ),
            (
                "\
-----BEGIN CERTIFICATE-----
invalidCertificate
-----END CERTIFICATE-----",
                "Parsing Error: Base64DecodeError",
            ),
        ];

        for (input, error) in expectations {
            let err = extract_public_key(input.into()).unwrap_err();
            match err {
                SignatureError::CertificateError { name } => {
                    assert_eq!(name, error)
                }
                e => assert!(false, format!("Unexpected error type: {:?}", e)),
            };
        }
    }
}
