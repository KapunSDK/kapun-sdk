// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

//! Configurable certificate construction for external signing providers.
use x509_cert::{
    SubjectPublicKeyInfo,
    der::{Decode, Encode},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

/// Prepare DER for signing outside Rust, e.g. with a platform HSM provider.
/// Inputs preserve the caller's certificate policy; private keys never cross this boundary.
pub fn prepare_certificate(
    issuer_der: &[u8],
    subject_der: &[u8],
    spki_der: &[u8],
    serial: &[u8],
    not_before: u64,
    not_after: u64,
    algorithm_der: &[u8],
    extensions_der: &[u8],
) -> x509_cert::der::Result<Vec<u8>> {
    use std::time::{Duration, UNIX_EPOCH};
    use x509_cert::der::Sequence;
    use x509_cert::{AlgorithmIdentifier, certificate::Version, ext::Extensions, time::Time};

    // RFC 5280 v3 fields, with no deprecated issuer/subject unique identifiers.
    #[derive(Sequence)]
    struct UnsignedCertificate {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
        version: Version,
        serial_number: SerialNumber,
        signature: AlgorithmIdentifier,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
        #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
        extensions: Extensions,
    }

    let invalid_time = || der::Error::from(der::ErrorKind::DateTime);
    if not_before >= not_after {
        return Err(invalid_time());
    }
    let starts = UNIX_EPOCH
        .checked_add(Duration::from_secs(not_before))
        .ok_or_else(invalid_time)?;
    let ends = UNIX_EPOCH
        .checked_add(Duration::from_secs(not_after))
        .ok_or_else(invalid_time)?;

    let tbs = UnsignedCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(serial)?,
        signature: AlgorithmIdentifier::from_der(algorithm_der)?,
        issuer: Name::from_der(issuer_der)?,
        validity: Validity::new(Time::try_from(starts)?, Time::try_from(ends)?),
        subject: Name::from_der(subject_der)?,
        subject_public_key_info: SubjectPublicKeyInfo::from_der(spki_der)?,
        extensions: Extensions::from_der(extensions_der)?,
    }
    .to_der()?;
    x509_cert::TbsCertificate::from_der(&tbs)?;
    Ok(tbs)
}

/// Assemble a certificate using a provider signature in the algorithm's encoding.
/// ECDSA signatures must use DER; the caller verifies the resulting signature.
pub fn complete_certificate(tbs: &[u8], signature: &[u8]) -> x509_cert::der::Result<Vec<u8>> {
    use x509_cert::der::{
        Sequence,
        asn1::{Any, BitString},
    };
    #[derive(Sequence)]
    struct SignedCertificate {
        tbs: Any,
        algorithm: x509_cert::AlgorithmIdentifier,
        signature: BitString,
    }
    let parsed = x509_cert::TbsCertificate::from_der(tbs)?;
    let certificate = SignedCertificate {
        tbs: Any::from_der(tbs)?,
        algorithm: parsed.signature().clone(),
        signature: BitString::from_bytes(signature)?,
    }
    .to_der()?;
    x509_cert::Certificate::from_der(&certificate)?;
    // Use kapun's parser as the shared certificate boundary.
    crate::extract_public_key(&certificate).map_err(|_| {
        der::Error::from(der::ErrorKind::Value {
            tag: der::Tag::Sequence,
        })
    })?;
    Ok(certificate)
}

pub fn san_extension(
    dns: &[String],
    uris: &[String],
) -> x509_cert::der::Result<x509_cert::ext::pkix::SubjectAltName> {
    let mut names = Vec::new();
    for value in dns {
        names.push(x509_cert::ext::pkix::name::GeneralName::DnsName(
            x509_cert::der::asn1::Ia5String::new(value)?,
        ));
    }
    for value in uris {
        names.push(
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                x509_cert::der::asn1::Ia5String::new(value)?,
            ),
        );
    }
    Ok(x509_cert::ext::pkix::SubjectAltName(names))
}
