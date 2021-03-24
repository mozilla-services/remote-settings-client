/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use thiserror::Error;
use x509_parser::{self, error as x509_errors, nom::Err as NomErr, pem::Pem};

pub use x509_parser::certificate::X509Certificate;

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("PEM content could not be parsed: {0}")]
    PEMError(#[from] NomErr<x509_errors::PEMError>),
    #[error("X509 content could not be parsed: {0}")]
    X509Error(#[from] NomErr<x509_errors::X509Error>),
    #[error("PEM is not a certificate: {0}")]
    WrongPEMType(String),
    #[error("no certificate was found in PEM")]
    EmptyPEM,
}

pub fn parse_certificate_chain(pem_bytes: &[u8]) -> Result<Vec<Pem>, X509Error> {
    // ``openssl x509 -inform PEM -in cert.pem -text``
    let blocks = split_pem(pem_bytes);

    let pems: Vec<Pem> = blocks
        .iter()
        .rev() // first will be root, last will be leaf.
        .map(|block| {
            let (_, pem) = x509_parser::pem::parse_x509_pem(&block)?;

            if pem.label != "CERTIFICATE" {
                return Err(X509Error::WrongPEMType(pem.label));
            }
            Ok(pem)
        })
        .collect::<Result<Vec<Pem>, _>>()?;

    if pems.len() == 0 {
        return Err(X509Error::EmptyPEM);
    }

    Ok(pems)
}

pub fn parse_x509_certificate<'a>(pem: &'a Pem) -> Result<X509Certificate<'a>, X509Error> {
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)?;
    Ok(cert)
}

fn split_pem(pem_content: &[u8]) -> Vec<&[u8]> {
    let mut blocks = vec![];

    let needle = b"-----BEGIN CERTIFICATE";
    let window = needle.len();
    let mut last = 0;
    if pem_content.len() > window {
        let mut i = 0;
        while i < pem_content.len() - window - 1 {
            let portion = &pem_content[i..i + window];
            if portion == needle && i > last {
                blocks.push(&pem_content[last..i]);
                last = i;
                i = i + window;
            } else {
                i = i + 1;
            }
        }
    }
    if last < pem_content.len() {
        blocks.push(&pem_content[last..]);
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::parse_certificate_chain;

    #[test]
    fn test_bad_pem_content() {
        let expectations: Vec<(&str, &str)> = vec![
            ("", "no certificate was found in PEM"),
            ("1", "PEM content could not be parsed: Parsing Error: MissingHeader"),
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
            let err = parse_certificate_chain(input.as_bytes()).unwrap_err();
            assert_eq!(err.to_string(), error);
        }
    }
}
