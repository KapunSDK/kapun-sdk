// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use crate::management::{Error, Result};
use der::{Decode, asn1::Any};
use josekit::jws::{self, JwsVerifier};
use x509_cert::AlgorithmIdentifier;

use crate::builder::encoding::{
    EcdsaSignature, MGF1, PssParameters, RSA_PSS, SHA256, SHA384, SHA512,
};
pub use crate::builder::{SignatureAlgorithm, SignatureEncoding};

pub fn signature_algorithm(algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
    Ok(crate::builder::signature_algorithm(algorithm)?)
}

/// Verify the declared algorithm, including PSS parameters, rather than inferring it from SPKI.
pub fn verify_signature(
    spki: &[u8],
    algorithm: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let algorithm = AlgorithmIdentifier::from_der(algorithm)?;
    let selected = decode_algorithm(&algorithm)?;
    let key = x509_cert::SubjectPublicKeyInfo::from_der(spki)?;
    if matches!(
        selected,
        SignatureAlgorithm::Ed25519 | SignatureAlgorithm::Ed448
    ) && (key.algorithm.oid != algorithm.oid || key.algorithm.parameters.is_some())
    {
        return Err(Error::InvalidSignature);
    }
    let key_error = |_| Error::InvalidSignature;
    use SignatureAlgorithm::*;
    let verifier: Box<dyn JwsVerifier> = match selected {
        Es256 => Box::new(jws::ES256.verifier_from_der(spki).map_err(key_error)?),
        Es384 => Box::new(jws::ES384.verifier_from_der(spki).map_err(key_error)?),
        Es512 => Box::new(jws::ES512.verifier_from_der(spki).map_err(key_error)?),
        Rs256 => Box::new(jws::RS256.verifier_from_der(spki).map_err(key_error)?),
        Rs384 => Box::new(jws::RS384.verifier_from_der(spki).map_err(key_error)?),
        Rs512 => Box::new(jws::RS512.verifier_from_der(spki).map_err(key_error)?),
        Ps256 => Box::new(jws::PS256.verifier_from_der(spki).map_err(key_error)?),
        Ps384 => Box::new(jws::PS384.verifier_from_der(spki).map_err(key_error)?),
        Ps512 => Box::new(jws::PS512.verifier_from_der(spki).map_err(key_error)?),
        Ed25519 | Ed448 => Box::new(jws::EdDSA.verifier_from_der(spki).map_err(key_error)?),
    };
    let signature = match component_size(selected) {
        Some(size) => {
            let values = EcdsaSignature::from_der(signature)?;
            let mut raw = vec![0; size * 2];
            for (component, offset) in
                [(values.r.as_bytes(), size), (values.s.as_bytes(), size * 2)]
            {
                if component.len() > size {
                    return Err(Error::InvalidSignature);
                }
                raw[offset - component.len()..offset].copy_from_slice(component);
            }
            raw
        }
        None => signature.to_vec(),
    };
    verifier
        .verify(message, &signature)
        .map_err(|_| Error::InvalidSignature)
}

pub(crate) fn encode_signature(
    algorithm: &[u8],
    signature: &[u8],
    encoding: SignatureEncoding,
) -> Result<Vec<u8>> {
    let selected = decode_algorithm(&AlgorithmIdentifier::from_der(algorithm)?)?;
    if let (SignatureEncoding::JoseRaw, Some(size)) = (encoding, component_size(selected)) {
        if signature.len() != size * 2 {
            return Err(Error::InvalidSignature);
        }
        return crate::builder::ecdsa_signature_to_der(signature).ok_or(Error::InvalidSignature);
    }
    Ok(signature.to_vec())
}

fn component_size(algorithm: SignatureAlgorithm) -> Option<usize> {
    match algorithm {
        SignatureAlgorithm::Es256 => Some(32),
        SignatureAlgorithm::Es384 => Some(48),
        SignatureAlgorithm::Es512 => Some(66),
        _ => None,
    }
}

fn decode_algorithm(algorithm: &AlgorithmIdentifier) -> Result<SignatureAlgorithm> {
    use SignatureAlgorithm::*;
    if algorithm.oid == RSA_PSS {
        let params: PssParameters = algorithm
            .parameters
            .as_ref()
            .ok_or(Error::UnsupportedAlgorithm)?
            .decode_as()?;
        let hash = params.hash.ok_or(Error::UnsupportedAlgorithm)?;
        let mask = params.mask.ok_or(Error::UnsupportedAlgorithm)?;
        let mask_hash: AlgorithmIdentifier = mask
            .parameters
            .as_ref()
            .ok_or(Error::UnsupportedAlgorithm)?
            .decode_as()?;
        check_null(&hash)?;
        check_null(&mask_hash)?;
        if mask.oid != MGF1 || mask_hash.oid != hash.oid || params.trailer.unwrap_or(1) != 1 {
            return Err(Error::UnsupportedAlgorithm);
        }
        return match (hash.oid, params.salt.unwrap_or(20)) {
            (SHA256, 32) => Ok(Ps256),
            (SHA384, 48) => Ok(Ps384),
            (SHA512, 64) => Ok(Ps512),
            _ => Err(Error::UnsupportedAlgorithm),
        };
    }
    let selected = match algorithm.oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => Es256,
        "1.2.840.10045.4.3.3" => Es384,
        "1.2.840.10045.4.3.4" => Es512,
        "1.2.840.113549.1.1.11" => Rs256,
        "1.2.840.113549.1.1.12" => Rs384,
        "1.2.840.113549.1.1.13" => Rs512,
        "1.3.101.112" => Ed25519,
        "1.3.101.113" => Ed448,
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    match selected {
        Rs256 | Rs384 | Rs512 => check_null(algorithm)?,
        _ if algorithm.parameters.is_some() => return Err(Error::UnsupportedAlgorithm),
        _ => (),
    }
    Ok(selected)
}

fn check_null(algorithm: &AlgorithmIdentifier) -> Result<()> {
    if algorithm
        .parameters
        .as_ref()
        .is_some_and(|v| v != &Any::null())
    {
        return Err(Error::UnsupportedAlgorithm);
    }
    Ok(())
}
