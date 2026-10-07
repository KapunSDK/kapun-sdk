// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    CertificateRole, ExtensionPresence, are_x509_name_equal, basic_constraints,
    is_basic_constraint_fulfilled, is_key_usage_correct,
};
use crate::parse_certificate;
use x509_parser::{
    prelude::{
        TbsCertificateStructureValidator, Validator, VecLogger, X509Certificate,
        X509ExtensionsValidator,
    },
    time::ASN1Time,
};

#[derive(Clone, Copy, Debug)]
pub enum ChainKind {
    Signing,
    Authorities,
}
#[derive(Clone, Copy, Debug)]
pub enum ChainEnd {
    Complete,
    Partial,
    Trusted,
}
#[derive(Clone, Copy, Debug)]
pub enum IssuerUsage {
    Required,
    IfPresent,
    Unchecked,
}

#[derive(Clone, Debug)]
pub struct ChainPolicy {
    pub kind: ChainKind,
    pub end: ChainEnd,
    pub issuer_usage: IssuerUsage,
    pub time: i64,
    pub trusted_anchors: Vec<Vec<u8>>,
    pub expected_spki: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ValidationError {
    pub index: usize,
    pub reason: String,
}
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Certificate {}: {}", self.index, self.reason)
    }
}
impl std::error::Error for ValidationError {}

pub(super) enum ConstraintCheck {
    Required,
    Unchecked,
}
pub(super) enum StructureCheck {
    Required,
    DecodeOnly,
}
pub(super) enum RootSignature {
    VerifySelfIssued,
    UnlessTrusted,
}
pub(super) struct ChainChecks {
    pub constraints: ConstraintCheck,
    pub structure: StructureCheck,
    pub root_signature: RootSignature,
    pub minimum_length: usize,
}

/// One chain engine for legacy provider APIs and the owned management facade.
pub fn validate_chain_with<F>(
    chain: &[Vec<u8>],
    policy: &ChainPolicy,
    verify: F,
) -> Result<(), ValidationError>
where
    F: Fn(&X509Certificate, &X509Certificate, &[u8]) -> Result<(), String>,
{
    let checks = ChainChecks {
        constraints: ConstraintCheck::Required,
        structure: StructureCheck::DecodeOnly,
        root_signature: RootSignature::VerifySelfIssued,
        minimum_length: 1,
    };
    validate_chain_inner(chain, policy, &checks, &verify)
}

pub fn is_valid_at(cert: &X509Certificate, time: i64) -> Result<bool, ()> {
    let time = ASN1Time::from_timestamp(time).map_err(|_| ())?;
    Ok(cert.validity().is_valid_at(time))
}

pub fn is_self_issued(cert: &X509Certificate) -> bool {
    are_x509_name_equal(&cert.subject, &cert.issuer)
}

pub(super) fn validate_chain_inner<F>(
    chain: &[Vec<u8>],
    policy: &ChainPolicy,
    checks: &ChainChecks,
    verify: &F,
) -> Result<(), ValidationError>
where
    F: Fn(&X509Certificate, &X509Certificate, &[u8]) -> Result<(), String>,
{
    let fail = |index, reason: &str| ValidationError {
        index,
        reason: reason.into(),
    };
    if chain.is_empty() {
        return Err(fail(0, "Certificate chain required"));
    }

    // Try every matching anchor; issuer names identify candidates, not trust.
    if matches!(policy.end, ChainEnd::Trusted)
        && !policy
            .trusted_anchors
            .contains(chain.last().ok_or_else(|| fail(0, "Empty chain"))?)
    {
        let last = parse_certificate(&chain[chain.len() - 1])
            .map_err(|_| fail(chain.len() - 1, "Invalid DER"))?;
        for anchor in &policy.trusted_anchors {
            let Ok(anchor_cert) = parse_certificate(anchor) else {
                continue;
            };
            if !are_x509_name_equal(&last.issuer, &anchor_cert.subject) {
                continue;
            }
            let mut candidate = chain.to_vec();
            candidate.push(anchor.clone());
            if validate_chain_inner(&candidate, policy, checks, verify).is_ok() {
                return Ok(());
            }
        }
        return Err(fail(chain.len() - 1, "No matching explicit trust anchor"));
    }
    if chain.len() < checks.minimum_length {
        return Err(fail(0, "Chain requires leaf and issuer"));
    }
    let mut parsed = Vec::with_capacity(chain.len());
    for (index, der) in chain.iter().enumerate() {
        let cert = parse_certificate(der).map_err(|_| fail(index, "Invalid DER"))?;
        if matches!(checks.structure, StructureCheck::Required) {
            let mut logger = VecLogger::default();
            if !TbsCertificateStructureValidator.validate(&cert, &mut logger)
                || !X509ExtensionsValidator.validate(&cert.extensions(), &mut logger)
            {
                return Err(fail(index, "Invalid certificate structure"));
            }
        }
        if !is_valid_at(&cert, policy.time).map_err(|_| fail(index, "Invalid validation time"))? {
            return Err(fail(index, "Certificate outside its validity period"));
        }
        parsed.push(cert);
    }
    if policy
        .expected_spki
        .as_ref()
        .is_some_and(|key| key.as_slice() != parsed[0].public_key().raw)
    {
        return Err(fail(0, "Certificate does not match the registered key"));
    }
    for (index, issuer) in parsed.iter().enumerate() {
        if index > 0
            || matches!(policy.kind, ChainKind::Authorities)
            || (index + 1 == parsed.len() && matches!(policy.end, ChainEnd::Trusted))
        {
            if !is_key_usage_correct(issuer, policy.issuer_usage) {
                return Err(fail(index, "CA requires keyCertSign usage"));
            }
            if matches!(checks.constraints, ConstraintCheck::Required) {
                let mut depth = 0;
                // RFC 5280 excludes the target, even when it is a CA.
                let target_offset = usize::from(matches!(policy.kind, ChainKind::Signing));
                for subordinate in parsed[..index].iter().skip(target_offset) {
                    if basic_constraints(subordinate)
                        .map_err(|_| fail(index, "Invalid basic constraints"))?
                        .is_some_and(|v| v.ca)
                        && !is_self_issued(subordinate)
                    {
                        depth += 1;
                    }
                }
                if !is_basic_constraint_fulfilled(
                    issuer,
                    depth,
                    CertificateRole::Authority,
                    ExtensionPresence::Required,
                )
                .map_err(|_| fail(index, "Invalid basic constraints"))?
                {
                    return Err(fail(index, "CA role or path length constraint violated"));
                }
            }
        }
        if index == 0 {
            continue;
        }
        let child = &parsed[index - 1];
        if !are_x509_name_equal(&child.issuer, &issuer.subject) {
            return Err(fail(
                index - 1,
                "Certificate issuer does not match chain order",
            ));
        }
        verify(issuer, child, &chain[index - 1]).map_err(|reason| ValidationError {
            index: index - 1,
            reason,
        })?;
    }
    let last = parsed.len() - 1;
    let root = &parsed[last];
    let self_issued = is_self_issued(root);
    if self_issued
        && (matches!(checks.root_signature, RootSignature::VerifySelfIssued)
            || !matches!(policy.end, ChainEnd::Trusted))
    {
        verify(root, root, &chain[last]).map_err(|reason| ValidationError {
            index: last,
            reason,
        })?;
    }
    if matches!(policy.end, ChainEnd::Complete) && !self_issued {
        return Err(fail(last, "Self-signed root required"));
    }
    Ok(())
}

/// Share self-issuance and signature checks across certificate roles and bindings.
pub fn has_self_signature<E, F>(cert: &X509Certificate, verify: F) -> Result<bool, E>
where
    F: FnOnce(&X509Certificate) -> Result<(), E>,
{
    if !is_self_issued(cert) {
        return Ok(false);
    }
    verify(cert)?;
    Ok(true)
}
