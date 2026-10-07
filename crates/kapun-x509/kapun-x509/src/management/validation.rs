// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use super::{CertificateInfo, Error, Result, inspect_certificate};
pub use crate::crypto::verify_certificate;
pub use crate::x509::{ChainEnd, ChainKind, ChainPolicy, IssuerUsage};
use crate::{parse_certificate, x509};

pub fn is_self_signed(input: &[u8]) -> Result<bool> {
    let cert =
        parse_certificate(input).map_err(|_| Error::Invalid("Invalid certificate".into()))?;
    x509::has_self_signature(&cert, |cert| {
        verify_certificate(input, cert.public_key().raw)
    })
}

pub fn check_validity(info: &CertificateInfo, time: i64) -> Result<()> {
    let cert =
        parse_certificate(&info.der).map_err(|_| Error::Invalid("Invalid certificate".into()))?;
    if !x509::is_valid_at(&cert, time)
        .map_err(|_| Error::Invalid("Invalid validation time".into()))?
    {
        return Err(Error::Invalid(
            "Certificate outside its validity period".into(),
        ));
    }
    Ok(())
}

pub fn validate_authority(input: &[u8], time: i64, usage: IssuerUsage) -> Result<CertificateInfo> {
    let info = inspect_certificate(input)?;
    check_validity(&info, time)?;
    let cert =
        parse_certificate(input).map_err(|_| Error::Invalid("Invalid certificate".into()))?;
    if !x509::is_basic_constraint_fulfilled(
        &cert,
        0,
        x509::CertificateRole::Authority,
        x509::ExtensionPresence::Required,
    )
    .map_err(|_| Error::Invalid("Invalid basic constraints".into()))?
        || !x509::is_key_usage_correct(&cert, usage)
    {
        return Err(Error::Invalid(
            "CA requires CA=true and keyCertSign usage".into(),
        ));
    }
    Ok(info)
}

/// Convert the shared chain validator's result into owned metadata for application bindings.
pub fn validate_chain(chain: &[Vec<u8>], policy: &ChainPolicy) -> Result<Vec<CertificateInfo>> {
    x509::validate_chain_with(chain, policy, |issuer, _, der| {
        verify_certificate(der, issuer.public_key().raw).map_err(|e| e.to_string())
    })?;
    chain.iter().map(|der| inspect_certificate(der)).collect()
}
