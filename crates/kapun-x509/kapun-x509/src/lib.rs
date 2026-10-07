#[cfg(feature = "builder")]
pub mod builder;
pub mod crypto;
#[cfg(feature = "management")]
pub mod management;
pub mod x509;
pub use x509_parser;
pub use x509_parser::der_parser;

#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    FailedToParseX509,
}
#[derive(Clone, Copy, Debug)]
pub enum TrustError {
    NoRootFound,
}
#[derive(Debug, Clone, Copy)]
pub enum X509Error {
    X509ParseError(ParseError),
    X509TrustError(TrustError),
    EmptyChain,
}
/// Parse exactly one certificate; reject trailing or concatenated input.
pub fn parse_certificate(
    cert: &[u8],
) -> Result<x509_parser::prelude::X509Certificate<'_>, ParseError> {
    let (remaining, parsed) =
        x509_parser::parse_x509_certificate(cert).map_err(|_| ParseError::FailedToParseX509)?;
    if !remaining.is_empty() {
        return Err(ParseError::FailedToParseX509);
    }
    Ok(parsed)
}

pub fn extract_public_key<T: AsRef<[u8]>>(cert: T) -> Result<Vec<u8>, ParseError> {
    Ok(parse_certificate(cert.as_ref())?.subject_pki.raw.to_vec())
}
