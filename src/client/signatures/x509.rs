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
    // Test URL parse error
    // Test Viaduct error
}
