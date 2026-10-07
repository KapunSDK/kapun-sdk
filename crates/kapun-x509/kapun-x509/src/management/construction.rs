// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use super::inspection::{check_extensions, inspect_name};
use super::{
    Error, Result, SignatureAlgorithm, SignatureEncoding, inspect_certificate, signature_algorithm,
};
use crate::crypto::encode_signature;
use der::{
    Decode, Encode, Sequence,
    asn1::{Any, Ia5String, ObjectIdentifier, OctetString},
};
use std::str::FromStr;
use x509_cert::{
    SubjectPublicKeyInfo,
    ext::{Extension, Extensions, pkix::*},
    name::{Name, RelativeDistinguishedName},
};

pub const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";
const KEY_USAGE_OID: &str = "2.5.29.15";
const SKI_OID: &str = "2.5.29.14";
const AKI_OID: &str = "2.5.29.35";
const AIA_OID: &str = "1.3.6.1.5.5.7.1.1";
const CA_ISSUERS_OID: &str = "1.3.6.1.5.5.7.48.2";
const QC_STATEMENTS_OID: &str = "1.3.6.1.5.5.7.1.3";
const QC_TYPE_OID: &str = "0.4.0.1862.1.6";

#[derive(Clone, Copy, Debug)]
pub enum NameOrder {
    Rfc4514,
    Input,
}
pub use crate::x509::CertificateRole;

#[derive(Clone, Debug)]
pub struct CertificateSpec {
    pub subject_der: Vec<u8>,
    pub issuer_certificate: Option<Vec<u8>>,
    pub spki_der: Vec<u8>,
    pub serial: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub algorithm: SignatureAlgorithm,
    pub role: CertificateRole,
    pub path_length: Option<u32>,
    pub key_usage: u16,
    pub dns_names: Vec<String>,
    pub uri_names: Vec<String>,
    pub ca_issuer_url: Option<String>,
    pub qc_types: Vec<String>,
    pub extensions: Vec<super::ExtensionInfo>,
}

// Use u32 because imported CA path limits may exceed x509-cert's u8 field.
#[derive(Sequence)]
pub(super) struct CaConstraints {
    #[asn1(default = "Default::default")]
    pub ca: bool,
    pub path_length: Option<u32>,
}

pub fn encode_name(input: &str, order: NameOrder) -> Result<Vec<u8>> {
    let name = Name::from_str(&normalize_name(input)?)?;
    if name.is_empty() {
        return Err(Error::Invalid("Subject required".into()));
    }
    let der = name.to_der()?;
    if matches!(order, NameOrder::Rfc4514) {
        return Ok(der);
    }
    // Input order preserves existing platform/BC subjects, e.g. C=CH,O=Example,CN=CA.
    let mut groups = Vec::<RelativeDistinguishedName>::from_der(&der)?;
    groups.reverse();
    Ok(groups.to_der()?)
}

pub fn prepare_certificate_spec(spec: &CertificateSpec) -> Result<Vec<u8>> {
    Name::from_der(&spec.subject_der)?;
    inspect_name(&spec.subject_der)?;
    SubjectPublicKeyInfo::from_der(&spec.spki_der)?;
    let issuer = spec
        .issuer_certificate
        .as_ref()
        .map(|v| inspect_certificate(v))
        .transpose()?;
    let issuer_der = issuer
        .as_ref()
        .map(|v| v.subject.der.as_slice())
        .unwrap_or(&spec.subject_der);
    let authority = matches!(spec.role, CertificateRole::Authority);
    if !authority && spec.path_length.is_some() {
        return Err(Error::Invalid("Leaf cannot have a CA path limit".into()));
    }
    let mut extensions = Vec::new();
    push_extension(
        &mut extensions,
        BASIC_CONSTRAINTS_OID,
        Criticality::Required,
        &CaConstraints {
            ca: authority,
            path_length: spec.path_length,
        },
    )?;
    push_extension(
        &mut extensions,
        KEY_USAGE_OID,
        Criticality::Required,
        &KeyUsage(
            der::flagset::FlagSet::<KeyUsages>::new(spec.key_usage)
                .map_err(|_| Error::Invalid("Invalid key usage".into()))?,
        ),
    )?;
    push_extension(
        &mut extensions,
        SKI_OID,
        Criticality::Optional,
        &SubjectKeyIdentifier::try_from(x509_cert::spki::SubjectPublicKeyInfoRef::from_der(
            &spec.spki_der,
        )?)?,
    )?;
    if let Some(issuer) = &issuer {
        let aki = issuer.ski.clone().unwrap_or(
            SubjectKeyIdentifier::try_from(x509_cert::spki::SubjectPublicKeyInfoRef::from_der(
                &issuer.spki_der,
            )?)?
            .0
            .as_bytes()
            .to_vec(),
        );
        // Match the existing platform AKI, including the issuer's name and serial.
        let identifier = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(aki)?),
            authority_cert_issuer: Some(vec![name::GeneralName::DirectoryName(Name::from_der(
                &issuer.issuer.der,
            )?)]),
            authority_cert_serial_number: Some(x509_cert::serial_number::SerialNumber::new(
                &issuer.serial,
            )?),
        };
        push_extension(&mut extensions, AKI_OID, Criticality::Optional, &identifier)?;
    }
    if !spec.dns_names.is_empty() || !spec.uri_names.is_empty() {
        push_extension(
            &mut extensions,
            super::SAN_OID,
            Criticality::Optional,
            &crate::builder::san_extension(&spec.dns_names, &spec.uri_names)?,
        )?;
    }
    if let Some(url) = &spec.ca_issuer_url {
        let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: ObjectIdentifier::new(CA_ISSUERS_OID)?,
            access_location: name::GeneralName::UniformResourceIdentifier(Ia5String::new(url)?),
        }]);
        push_extension(&mut extensions, AIA_OID, Criticality::Optional, &aia)?;
    }
    if !spec.qc_types.is_empty() {
        #[derive(Sequence)]
        struct Statement {
            oid: ObjectIdentifier,
            info: Any,
        }
        let types = spec
            .qc_types
            .iter()
            .map(|oid| ObjectIdentifier::new(oid))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let statement = Statement {
            oid: ObjectIdentifier::new(QC_TYPE_OID)?,
            info: Any::encode_from(&types)?,
        };
        push_extension(
            &mut extensions,
            QC_STATEMENTS_OID,
            Criticality::Optional,
            &vec![statement],
        )?;
    }
    for extension in &spec.extensions {
        // Custom extensions cannot replace constraints or duplicate generated fields.
        extensions.push(Extension {
            extn_id: ObjectIdentifier::new(&extension.oid)?,
            critical: extension.critical,
            extn_value: OctetString::new(extension.value_der.clone())?,
        });
    }
    check_extensions(&extensions)?;
    Ok(crate::builder::prepare_certificate(
        issuer_der,
        &spec.subject_der,
        &spec.spki_der,
        &spec.serial,
        spec.not_before,
        spec.not_after,
        &signature_algorithm(spec.algorithm)?,
        &extensions.to_der()?,
    )?)
}

pub fn complete_certificate_signed(
    tbs: &[u8],
    signature: &[u8],
    encoding: SignatureEncoding,
    issuer_spki: &[u8],
) -> Result<Vec<u8>> {
    let parsed = x509_cert::TbsCertificate::from_der(tbs)?;
    let signature = encode_signature(&parsed.signature().to_der()?, signature, encoding)?;
    let result = crate::builder::complete_certificate(tbs, &signature)?;
    super::verify_certificate(&result, issuer_spki)?;
    Ok(result)
}

enum Criticality {
    Required,
    Optional,
}
fn push_extension(
    extensions: &mut Extensions,
    oid: &str,
    criticality: Criticality,
    value: &impl Encode,
) -> Result<()> {
    extensions.push(Extension {
        extn_id: ObjectIdentifier::new(oid)?,
        critical: matches!(criticality, Criticality::Required),
        extn_value: OctetString::new(value.to_der()?)?,
    });
    Ok(())
}

// Accept platform DN spacing/aliases without rewriting escaped attribute values.
fn normalize_name(input: &str) -> Result<String> {
    let mut output = String::new();
    let mut attribute = String::new();
    let mut in_value = false;
    let mut escaped = false;
    let mut quoted = false;
    let mut hex_tail = false;
    for character in input.chars() {
        if !in_value {
            if character != '=' {
                attribute.push(character);
                continue;
            }
            let key = attribute.trim();
            let oid = match key.to_ascii_uppercase().as_str() {
                "ORGANIZATIONIDENTIFIER" => "2.5.4.97",
                "EMAILADDRESS" | "E" => "1.2.840.113549.1.9.1",
                "SERIALNUMBER" => "2.5.4.5",
                "CN" => "2.5.4.3",
                "C" => "2.5.4.6",
                "O" => "2.5.4.10",
                "OU" => "2.5.4.11",
                "L" => "2.5.4.7",
                "ST" => "2.5.4.8",
                "STREET" => "2.5.4.9",
                "DC" => "0.9.2342.19200300.100.1.25",
                "UID" => "0.9.2342.19200300.100.1.1",
                _ => key.strip_prefix("OID.").unwrap_or(key),
            };
            output.push_str(oid);
            output.push('=');
            attribute.clear();
            in_value = true;
            continue;
        }
        if escaped {
            output.push(character);
            escaped = false;
            hex_tail = character.is_ascii_hexdigit();
            continue;
        }
        if hex_tail {
            if !character.is_ascii_hexdigit() {
                return Err(Error::Invalid("Incomplete name escape".into()));
            }
            output.push(character);
            hex_tail = false;
            continue;
        }
        if character == '\\' {
            output.push(character);
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted && matches!(character, ',' | '+' | ';') {
            output.push('\\');
        }
        if !quoted && matches!(character, ',' | '+') {
            in_value = false;
        }
        output.push(character);
    }
    if escaped || hex_tail || quoted || !attribute.trim().is_empty() || !in_value {
        return Err(Error::Invalid("Invalid distinguished name".into()));
    }
    Ok(output)
}
