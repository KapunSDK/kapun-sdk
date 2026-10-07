// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Error, Result};
use base64::{Engine, prelude::BASE64_STANDARD};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use x509_cert::{
    Certificate, SubjectPublicKeyInfo,
    ext::{Extensions, pkix::*},
    name::Name,
};

pub const CERTIFICATE_LABEL: &str = "CERTIFICATE";
pub const CSR_LABEL: &str = "CERTIFICATE REQUEST";
pub const SAN_OID: &str = "2.5.29.17";

#[derive(Clone, Debug)]
pub struct NameAttribute {
    pub rdn: u32,
    pub oid: String,
    pub value: String,
    pub value_der: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NameInfo {
    pub der: Vec<u8>,
    pub display: String,
    pub attributes: Vec<NameAttribute>,
}

#[derive(Clone, Debug)]
pub struct ExtensionInfo {
    pub oid: String,
    pub critical: bool,
    pub value_der: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CertificateInfo {
    pub der: Vec<u8>,
    pub fingerprint: String,
    pub serial: Vec<u8>,
    pub subject: NameInfo,
    pub issuer: NameInfo,
    pub spki_der: Vec<u8>,
    pub algorithm_der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub path_length: Option<u32>,
    pub key_usage: Option<u16>,
    pub extended_key_usage: Vec<String>,
    pub dns_names: Vec<String>,
    pub uri_names: Vec<String>,
    pub ski: Option<Vec<u8>>,
    pub aki: Option<Vec<u8>>,
    pub extensions: Vec<ExtensionInfo>,
}

/// Parsing consumes one complete DER object; it never establishes trust.
pub fn inspect_certificate(input: &[u8]) -> Result<CertificateInfo> {
    let certificate = Certificate::from_der(input)?;
    let tbs = certificate.tbs_certificate();
    let extensions = tbs.extensions().cloned().unwrap_or_default();
    check_extensions(&extensions)?;
    let parsed = crate::parse_certificate(input)
        .map_err(|_| Error::Invalid("Invalid certificate".into()))?;
    let constraints = crate::x509::basic_constraints(&parsed)
        .map_err(|_| Error::Invalid("Invalid basic constraints".into()))?;
    let usages = tbs.get_extension::<KeyUsage>()?.map(|(_, v)| v.0.bits());
    let extended = tbs
        .get_extension::<ExtendedKeyUsage>()?
        .map(|(_, v)| v.0)
        .unwrap_or_default();
    let san = tbs
        .get_extension::<SubjectAltName>()?
        .map(|(_, v)| v.0)
        .unwrap_or_default();
    let ski = tbs
        .get_extension::<SubjectKeyIdentifier>()?
        .map(|(_, v)| v.0.as_bytes().to_vec());
    let aki = tbs
        .get_extension::<AuthorityKeyIdentifier>()?
        .and_then(|(_, v)| v.key_identifier.map(|id| id.as_bytes().to_vec()));
    let (dns_names, uri_names) = san_names(&san);

    Ok(CertificateInfo {
        der: input.to_vec(),
        fingerprint: hex(&Sha256::digest(input)),
        serial: tbs.serial_number().as_bytes().to_vec(),
        subject: inspect_name(&tbs.subject().to_der()?)?,
        issuer: inspect_name(&tbs.issuer().to_der()?)?,
        spki_der: crate::extract_public_key(input)
            .map_err(|_| Error::Invalid("Invalid public key".into()))?,
        algorithm_der: certificate.signature_algorithm().to_der()?,
        not_before: tbs
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs()
            .try_into()
            .map_err(|_| Error::Invalid("Invalid validity timestamp".into()))?,
        not_after: tbs
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs()
            .try_into()
            .map_err(|_| Error::Invalid("Invalid validity timestamp".into()))?,
        is_ca: constraints.as_ref().is_some_and(|v| v.ca),
        path_length: constraints.and_then(|v| v.path_len_constraint),
        key_usage: usages,
        extended_key_usage: extended.iter().map(ToString::to_string).collect(),
        dns_names,
        uri_names,
        ski,
        aki,
        extensions: extension_info(&extensions),
    })
}

pub fn inspect_name(input: &[u8]) -> Result<NameInfo> {
    let name = Name::from_der(input)?;
    let (remaining, parsed) = x509_parser::prelude::X509Name::from_der(input)
        .map_err(|_| Error::Invalid("Invalid distinguished name".into()))?;
    if !remaining.is_empty() {
        return Err(Error::Invalid("Trailing name data".into()));
    }
    let mut attributes = Vec::new();
    for (rdn, values) in parsed.iter_rdn().enumerate() {
        for (attribute, value) in values.iter().enumerate() {
            // Keep the encoded value for non-text attributes and exact round trips.
            let value_der = name
                .iter_rdn()
                .nth(rdn)
                .and_then(|group| group.iter().nth(attribute))
                .ok_or_else(|| Error::Invalid("Invalid name attribute".into()))?
                .value
                .to_der()?;
            attributes.push(NameAttribute {
                rdn: rdn
                    .try_into()
                    .map_err(|_| Error::Invalid("Name too large".into()))?,
                oid: value.attr_type().to_string(),
                value: value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|_| format!("#{}", hex(&value_der))),
                value_der,
            });
        }
    }
    Ok(NameInfo {
        der: input.to_vec(),
        display: name.to_string(),
        attributes,
    })
}

/// Owned boundary for the shared X.509 name comparison.
pub fn names_equal(left: &[u8], right: &[u8]) -> Result<bool> {
    let parse = |input| {
        let (remaining, name) = x509_parser::prelude::X509Name::from_der(input)
            .map_err(|_| Error::Invalid("Invalid distinguished name".into()))?;
        if !remaining.is_empty() {
            return Err(Error::Invalid("Trailing name data".into()));
        }
        Ok(name)
    };
    Ok(crate::x509::are_x509_name_equal(
        &parse(left)?,
        &parse(right)?,
    ))
}

pub fn matches_public_key(certificate: &[u8], spki: &[u8]) -> Result<bool> {
    SubjectPublicKeyInfo::from_der(spki)?;
    Ok(inspect_certificate(certificate)?.spki_der == spki)
}

pub fn parse_pem_chain(input: &str) -> Result<Vec<Vec<u8>>> {
    let result = parse_pem(input, CERTIFICATE_LABEL)?;
    for certificate in &result {
        inspect_certificate(certificate)?;
    }
    Ok(result)
}

pub fn encode_pem_chain(chain: &[Vec<u8>]) -> Result<String> {
    let mut output = String::new();
    for certificate in chain {
        inspect_certificate(certificate)?;
        output.push_str(&encode_pem(CERTIFICATE_LABEL, certificate));
    }
    Ok(output)
}

pub fn public_key_pem(spki: &[u8]) -> Result<String> {
    SubjectPublicKeyInfo::from_der(spki)?;
    Ok(encode_pem("PUBLIC KEY", spki))
}

pub(super) fn encode_pem(label: &str, der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new(label, der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

pub(super) fn parse_pem(input: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut remaining = input.trim();
    let mut result = Vec::new();
    while !remaining.is_empty() {
        let body = remaining
            .strip_prefix(&begin)
            .ok_or_else(|| Error::Invalid(format!("Expected {label} PEM block")))?;
        let (body, tail) = body
            .split_once(&end)
            .ok_or_else(|| Error::Invalid("Incomplete PEM block".into()))?;
        let base64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = BASE64_STANDARD
            .decode(base64)
            .map_err(|_| Error::Invalid("Invalid PEM base64".into()))?;
        result.push(der);
        remaining = tail.trim();
    }
    if result.is_empty() {
        return Err(Error::Invalid("Empty PEM input".into()));
    }
    Ok(result)
}

pub(super) fn check_extensions(extensions: &Extensions) -> Result<()> {
    let mut oids = HashSet::new();
    for extension in extensions {
        if !oids.insert(extension.extn_id) {
            return Err(Error::Invalid("Duplicate extension".into()));
        }
    }
    Ok(())
}

pub(super) fn extension_info(extensions: &Extensions) -> Vec<ExtensionInfo> {
    extensions
        .iter()
        .map(|e| ExtensionInfo {
            oid: e.extn_id.to_string(),
            critical: e.critical,
            value_der: e.extn_value.as_bytes().to_vec(),
        })
        .collect()
}

pub(super) fn san_names(names: &[name::GeneralName]) -> (Vec<String>, Vec<String>) {
    let dns = names
        .iter()
        .filter_map(|n| match n {
            name::GeneralName::DnsName(v) => Some(v.to_string()),
            _ => None,
        })
        .collect();
    let uri = names
        .iter()
        .filter_map(|n| match n {
            name::GeneralName::UniformResourceIdentifier(v) => Some(v.to_string()),
            _ => None,
        })
        .collect();
    (dns, uri)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

use x509_parser::prelude::FromDer;
