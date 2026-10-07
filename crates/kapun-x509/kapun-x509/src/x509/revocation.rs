// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use super::{ChainEnd, ChainPolicy, ValidationError, are_x509_name_equal, validate_chain_with};
use x509_parser::{
    der_parser::{oid, oid::Oid},
    extensions::ParsedExtension,
    prelude::X509Certificate,
    revocation_list::CertificateRevocationList,
    time::ASN1Time,
};

const DELTA_CRL: Oid<'static> = oid!(2.5.29.27);
const ISSUING_POINT: Oid<'static> = oid!(2.5.29.28);
const CERTIFICATE_ISSUER: Oid<'static> = oid!(2.5.29.29);

/// Validate a chain with supplied, directly issued full CRLs; no network access.
/// Every non-anchor certificate needs authenticated, current revocation data.
/// Delta, scoped and indirect CRLs are unsupported and cannot establish status.
pub fn validate_chain_crls_with<F, C>(
    chain: &[Vec<u8>],
    policy: &ChainPolicy,
    crls: &[Vec<u8>],
    verify: F,
    verify_crl: C,
) -> Result<(), ValidationError>
where
    F: Fn(&X509Certificate, &X509Certificate, &[u8]) -> Result<(), String>,
    C: Fn(&X509Certificate, &CertificateRevocationList) -> Result<(), String>,
{
    if matches!(policy.end, ChainEnd::Partial) {
        return Err(ValidationError {
            index: chain.len().saturating_sub(1),
            reason: "CRL validation requires a complete or anchored chain".into(),
        });
    }
    validate_chain_with(chain, policy, |issuer, subject, der| {
        verify(issuer, subject, der)?;
        if issuer == subject {
            return Ok(());
        }
        check_crls(issuer, subject, crls, policy.time, &verify_crl)
    })
}

fn check_crls<C>(
    issuer: &X509Certificate,
    subject: &X509Certificate,
    crls: &[Vec<u8>],
    time: i64,
    verify: &C,
) -> Result<(), String>
where
    C: Fn(&X509Certificate, &CertificateRevocationList) -> Result<(), String>,
{
    let time = ASN1Time::from_timestamp(time).map_err(|_| "Invalid validation time")?;
    let usage = issuer.key_usage().map_err(|_| "Invalid CRL signer usage")?;
    if usage.is_some_and(|usage| !usage.value.crl_sign()) {
        return Err("CRL signer requires cRLSign usage".into());
    }

    let mut candidates = Vec::new();
    for der in crls {
        let Ok((remaining, crl)) = x509_parser::parse_x509_crl(der) else {
            continue;
        };
        if !remaining.is_empty()
            || !are_x509_name_equal(crl.issuer(), &issuer.subject)
            || crl.last_update() > time
            || crl.next_update().is_none_or(|next| time >= next)
            || !full_crl(&crl)
            || verify(issuer, &crl).is_err()
        {
            continue;
        }
        candidates.push(crl);
    }

    // Prefer the latest authenticated full CRL, independent of input order.
    let latest = candidates
        .iter()
        .map(|crl| (crl.last_update(), crl.crl_number()))
        .max()
        .ok_or("No valid CRL for certificate issuer")?;
    for crl in &candidates {
        if (crl.last_update(), crl.crl_number()) != latest {
            continue;
        }
        if crl
            .iter_revoked_certificates()
            .any(|entry| entry.serial() == &subject.serial && entry.revocation_date <= time)
        {
            return Err("Certificate revoked".into());
        }
    }
    Ok(())
}

fn full_crl(crl: &CertificateRevocationList) -> bool {
    if crl.tbs_cert_list.extensions_map().is_err() {
        return false;
    }
    for extension in crl.extensions() {
        // A full-CRL checker cannot claim coverage for deltas or scoped lists.
        if extension.oid == DELTA_CRL || extension.oid == ISSUING_POINT {
            return false;
        }
        match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(_) | ParsedExtension::CRLNumber(_) => {}
            ParsedExtension::ParseError { .. } => return false,
            _ if extension.critical => return false,
            _ => {}
        }
    }
    for entry in crl.iter_revoked_certificates() {
        if entry.extensions_map().is_err() {
            return false;
        }
        for extension in entry.extensions() {
            // certificateIssuer denotes an indirect CRL, which needs separate processing.
            if extension.oid == CERTIFICATE_ISSUER {
                return false;
            }
            match extension.parsed_extension() {
                ParsedExtension::ReasonCode(_) | ParsedExtension::InvalidityDate(_) => {}
                ParsedExtension::ParseError { .. } => return false,
                _ if extension.critical => return false,
                _ => {}
            }
        }
    }
    true
}
