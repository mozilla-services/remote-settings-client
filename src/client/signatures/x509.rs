use {
    super::SignatureError,
    log::debug,
    url::ParseError,
    url::Url,
    viaduct::Error as ViaductError,
    viaduct::Request,
    x509_parser::{self, error as x509_errors, nom::Err as NomErr},
};

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

pub fn fetch_public_key(x5u: &str) -> Result<Vec<u8>, SignatureError> {
    debug!("Fetching certificate {}", x5u);

    let resp = Request::get(Url::parse(&x5u)?).send()?;

    if resp.status != 200 {
        return Err(SignatureError::CertificateError {
            name: format!("PEM could not be downloaded (HTTP {})", resp.status),
        });
    }

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

    Ok(x509
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::{fetch_public_key, SignatureError};
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};

    #[test]
    fn test_bad_url() {
        let err = fetch_public_key("%^").unwrap_err();
        match err {
            SignatureError::CertificateError { name } => {
                assert_eq!(name, "relative URL without a base")
            }
            _ => assert!(false),
        };
    }

    #[test]
    fn test_download_error() {
        let err = fetch_public_key("http://localhost:9999/bad").unwrap_err();
        match err {
            SignatureError::CertificateError { name } => {
                assert!(name.contains("Network error: error sending request"))
            }
            _ => assert!(false),
        };
    }

    #[test]
    fn test_bad_status() {
        let mock_server = MockServer::start();
        let mock_server_address = mock_server.url("/file.pem");

        let mut pem_mock = Mock::new()
            .expect_method(GET)
            .expect_path("/file.pem")
            .return_status(404)
            .create_on(&mock_server);

        let err = fetch_public_key(&mock_server_address).unwrap_err();
        match err {
            SignatureError::CertificateError { name } => {
                assert!(
                    name.contains("PEM could not be downloaded (HTTP 404)"),
                    name
                )
            }
            _ => assert!(false),
        };

        pem_mock.delete();
    }
}
