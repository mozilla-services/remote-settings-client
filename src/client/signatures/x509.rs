/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use thiserror::Error;
use x509_parser::{self, error as x509_errors, nom::Err as NomErr};

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("PEM content could not be parsed: {0}")]
    PEMError(#[from] NomErr<x509_errors::PEMError>),
    #[error("X509 content could not be parsed: {0}")]
    X509Error(#[from] NomErr<x509_errors::X509Error>),
    #[error("PEM is not a certificate: {0}")]
    WrongPEMType(String),
}

pub fn extract_public_key(pem_bytes: Vec<u8>) -> Result<Vec<u8>, X509Error> {
    // ``openssl x509 -inform PEM -in cert.pem -text``
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)?;
    if pem.label != "CERTIFICATE" {
        return Err(X509Error::WrongPEMType(pem.label));
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
    use super::extract_public_key;

    #[test]
    fn test_bad_pem_content() {
        let expectations: Vec<(&str, &str)> = vec![
            (
                "%^",
                "PEM content could not be parsed: Parsing Error: MissingHeader",
            ),
            (
                "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
bGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTFFMEMGA1UEAww8Q29u
-----END ENCRYPTED PRIVATE KEY-----",
                "PEM is not a certificate: ENCRYPTED",
            ),
            (
                "\
-----BEGIN CERTIFICATE-----
invalidCertificate
-----END CERTIFICATE-----",
                "PEM content could not be parsed: Parsing Error: Base64DecodeError",
            ),
        ];

        for (input, error) in expectations {
            let err = extract_public_key(input.into()).unwrap_err();
            assert_eq!(err.to_string(), error);
        }
    }
}
