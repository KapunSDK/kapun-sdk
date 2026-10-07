#[cfg(feature = "management")]
mod signing;
#[cfg(feature = "management")]
pub use signing::{
    SignatureAlgorithm, SignatureEncoding, signature_algorithm,
    verify_signature as verify_signed_data,
};

use kapun_crypto_provider::KapunCryptoProvider;

use kapun_crypto_provider::oid_registry::Oid;
use x509_parser::{der_parser::oid, prelude::X509Certificate};

pub const OID_SIG_MLDSA44: Oid<'static> = oid!(2.16.840.1.101.3.4.3.17);
pub const OID_SIG_MLDSA65: Oid<'static> = oid!(2.16.840.1.101.3.4.3.18);
pub const OID_SIG_MLDSA87: Oid<'static> = oid!(2.16.840.1.101.3.4.3.19);

#[derive(Debug, Clone, Copy)]
pub enum SignatureError {
    UnknownAlgorithm,
    InvalidPublicKey,
    InvalidSignature,
    UnsupportedSignatureAlgorithm,
    Other,
}

pub fn verify_signature<Provider: KapunCryptoProvider>(
    issuer: &X509Certificate,
    subject: &X509Certificate,
) -> Result<(), SignatureError> {
    verify_signature_with(issuer.public_key().raw, subject, |spki, subject| {
        verify_data::<Provider>(
            spki,
            &subject.signature_algorithm.algorithm,
            subject.tbs_certificate.as_ref(),
            &subject.signature_value.data,
        )
    })
}

fn verify_data<Provider: KapunCryptoProvider>(
    spki: &[u8],
    algorithm: &Oid,
    data: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let verifier = Provider::verifier_for_oid(spki.to_vec(), algorithm.clone())
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    verifier
        .kapun_verify(data.to_vec(), signature.to_vec())
        .map_err(|_| SignatureError::InvalidSignature)
}

pub fn verify_crl<Provider: KapunCryptoProvider>(
    issuer: &X509Certificate,
    crl: &x509_parser::revocation_list::CertificateRevocationList,
) -> Result<(), SignatureError> {
    check_signature(
        &crl.tbs_cert_list.signature,
        &crl.signature_algorithm,
        crl.signature_value.unused_bits,
    )?;
    verify_data::<Provider>(
        issuer.public_key().raw,
        &crl.signature_algorithm.algorithm,
        crl.tbs_cert_list.as_ref(),
        &crl.signature_value.data,
    )
}

fn verify_signature_with<E, F>(spki: &[u8], subject: &X509Certificate, verify: F) -> Result<(), E>
where
    E: From<SignatureError>,
    F: FnOnce(&[u8], &X509Certificate) -> Result<(), E>,
{
    check_signature(
        &subject.tbs_certificate.signature,
        &subject.signature_algorithm,
        subject.signature_value.unused_bits,
    )?;
    verify(spki, subject)
}

fn check_signature(
    inner: &x509_parser::x509::AlgorithmIdentifier,
    outer: &x509_parser::x509::AlgorithmIdentifier,
    unused_bits: u8,
) -> Result<(), SignatureError> {
    if inner != outer || unused_bits != 0 {
        return Err(SignatureError::InvalidSignature);
    }
    Ok(())
}

#[cfg(feature = "management")]
pub fn verify_certificate(certificate: &[u8], issuer_spki: &[u8]) -> crate::management::Result<()> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(certificate)?;
    let parsed = crate::parse_certificate(certificate)
        .map_err(|_| crate::management::Error::InvalidSignature)?;
    verify_signature_with(issuer_spki, &parsed, |spki, subject| {
        verify_signed_data(
            spki,
            &cert.signature_algorithm().to_der()?,
            subject.tbs_certificate.as_ref(),
            &subject.signature_value.data,
        )
    })
}

#[cfg(feature = "management")]
pub(crate) use signing::encode_signature;
