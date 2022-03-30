/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use thiserror::Error;
use x509_parser::{self, error as x509_errors, nom::Err as NomErr, pem::Pem};

pub use x509_parser::certificate::X509Certificate;

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("PEM content could not be parsed: {0}")]
    PEMError(#[from] x509_errors::PEMError),
    #[error("X509 content could not be parsed: {0}")]
    ParseError(#[from] NomErr<x509_errors::X509Error>),
    #[error("PEM is not a certificate: {0}")]
    WrongPEMType(String),
    #[error("no certificate was found in PEM")]
    EmptyPEM,
}

pub fn parse_certificate_chain(pem_bytes: &[u8]) -> Result<Vec<Pem>, X509Error> {
    // ``openssl x509 -inform PEM -in cert.pem -text``
    let pems: Vec<Pem> = Pem::iter_from_buffer(pem_bytes)
        .map(|res| match res {
            Ok(pem) => {
                if pem.label != "CERTIFICATE" {
                    return Err(X509Error::WrongPEMType(pem.label));
                }
                Ok(pem)
            }
            Err(e) => Err(e.into()),
        })
        .collect::<Result<Vec<Pem>, _>>()?
        .into_iter()
        .rev() // first will be root, last will be leaf.
        .collect();

    if pems.is_empty() {
        return Err(X509Error::EmptyPEM);
    }

    Ok(pems)
}

pub fn parse_x509_certificate(pem: &Pem) -> Result<X509Certificate, X509Error> {
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)?;
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::parse_certificate_chain;

    #[test]
    fn test_bad_pem_content() {
        let expectations: Vec<(&str, &str)> = vec![
            ("", "no certificate was found in PEM"),
            ("1", "no certificate was found in PEM"),
            ("%^", "no certificate was found in PEM"),
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
                "PEM content could not be parsed: base64 decode error",
            ),
            (
                "\
-----BEGIN CERTIFICATE-----
bGxhIEFNTyBQcm9kdWN0aW9uIFNp
-----BEGIN CERTIFICATE-----",
                "PEM content could not be parsed: incomplete PEM",
            ),
        ];

        for (input, error) in expectations {
            let err = parse_certificate_chain(input.as_bytes()).unwrap_err();
            assert_eq!(err.to_string(), error);
        }
    }
}
