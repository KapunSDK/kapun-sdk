// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use super::inspection::{check_extensions, encode_pem, extension_info, parse_pem};
use super::{Error, ExtensionInfo, NameInfo, Result, SignatureAlgorithm, SignatureEncoding};
use der::{Decode, Encode, asn1::BitString};
use std::collections::HashSet;
use x509_cert::{
    SubjectPublicKeyInfo,
    ext::Extensions,
    name::Name,
    request::{CertReq, CertReqInfo, ExtensionReq},
};

const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";

#[derive(Clone, Debug)]
pub struct CsrInfo {
    pub der: Vec<u8>,
    pub subject: NameInfo,
    pub spki_der: Vec<u8>,
    pub extensions: Vec<ExtensionInfo>,
}

pub fn prepare_csr(
    subject_der: &[u8],
    spki: &[u8],
    dns: &[String],
    uris: &[String],
) -> Result<Vec<u8>> {
    let mut attributes = Default::default();
    if !dns.is_empty() || !uris.is_empty() {
        let san = crate::builder::san_extension(dns, uris)?;
        let extension = x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new(super::SAN_OID)?,
            critical: false,
            extn_value: der::asn1::OctetString::new(san.to_der()?)?,
        };
        let attribute = x509_cert::attr::Attribute::try_from(ExtensionReq(vec![extension]))?;
        attributes = x509_cert::attr::Attributes::try_from(vec![attribute])?;
    }
    Ok(CertReqInfo {
        version: Default::default(),
        subject: Name::from_der(subject_der)?,
        public_key: SubjectPublicKeyInfo::from_der(spki)?,
        attributes,
    }
    .to_der()?)
}

pub fn complete_csr(
    info: &[u8],
    algorithm: SignatureAlgorithm,
    signature: &[u8],
    encoding: SignatureEncoding,
) -> Result<Vec<u8>> {
    let algorithm_der = super::signature_algorithm(algorithm)?;
    let signature = crate::crypto::encode_signature(&algorithm_der, signature, encoding)?;
    let request = CertReq {
        info: CertReqInfo::from_der(info)?,
        algorithm: x509_cert::AlgorithmIdentifier::from_der(&algorithm_der)?,
        signature: BitString::from_bytes(&signature)?,
    };
    let der = request.to_der()?;
    verify_csr(&der)?;
    Ok(der)
}

pub fn inspect_csr(input: &[u8]) -> Result<CsrInfo> {
    let csr = CertReq::from_der(input)?;
    let mut extensions = Vec::new();
    let mut oids = HashSet::new();
    for attr in csr.info.attributes.iter() {
        if !oids.insert(attr.oid) {
            return Err(Error::Invalid("Duplicate CSR attribute".into()));
        }
        if attr.oid.to_string() != EXTENSION_REQUEST_OID {
            continue;
        }
        if attr.values.len() != 1 {
            return Err(Error::Invalid("Invalid CSR extension request".into()));
        }
        extensions = attr
            .values
            .iter()
            .next()
            .ok_or_else(|| Error::Invalid("Missing CSR extension request".into()))?
            .decode_as::<Extensions>()?;
    }
    check_extensions(&extensions)?;
    Ok(CsrInfo {
        der: input.to_vec(),
        subject: super::inspect_name(&csr.info.subject.to_der()?)?,
        spki_der: csr.info.public_key.to_der()?,
        extensions: extension_info(&extensions),
    })
}

pub fn verify_csr(input: &[u8]) -> Result<CsrInfo> {
    let info = inspect_csr(input)?;
    let csr = CertReq::from_der(input)?;
    super::verify_signature(
        &info.spki_der,
        &csr.algorithm.to_der()?,
        &csr.info.to_der()?,
        csr.signature.as_bytes().ok_or(Error::InvalidSignature)?,
    )?;
    Ok(info)
}

pub fn parse_pem_csr(input: &str) -> Result<Vec<u8>> {
    let mut requests = parse_pem(input, super::CSR_LABEL)?;
    if requests.len() != 1 {
        return Err(Error::Invalid("One CSR required".into()));
    }
    let request = requests.remove(0);
    inspect_csr(&request)?;
    Ok(request)
}

pub fn encode_pem_csr(input: &[u8]) -> Result<String> {
    inspect_csr(input)?;
    Ok(encode_pem(super::CSR_LABEL, input))
}
