// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

use der::{
    Encode, Sequence,
    asn1::{Any, ObjectIdentifier, Uint},
};
use x509_cert::AlgorithmIdentifier;

pub(crate) const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
pub(crate) const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
pub(crate) const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(crate) const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub(crate) const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    Es256,
    Es384,
    Es512,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Ed25519,
    Ed448,
}
#[derive(Clone, Copy, Debug)]
pub enum SignatureEncoding {
    JoseRaw,
    Certificate,
}

#[derive(Sequence)]
pub(crate) struct PssParameters {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub hash: Option<AlgorithmIdentifier>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub mask: Option<AlgorithmIdentifier>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub salt: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub trailer: Option<u32>,
}

#[derive(Sequence)]
pub(crate) struct EcdsaSignature {
    pub r: Uint,
    pub s: Uint,
}

pub fn signature_algorithm(algorithm: SignatureAlgorithm) -> der::Result<Vec<u8>> {
    use SignatureAlgorithm::*;
    let (oid, parameters) = match algorithm {
        Es256 => ("1.2.840.10045.4.3.2", None),
        Es384 => ("1.2.840.10045.4.3.3", None),
        Es512 => ("1.2.840.10045.4.3.4", None),
        Rs256 => ("1.2.840.113549.1.1.11", Some(Any::null())),
        Rs384 => ("1.2.840.113549.1.1.12", Some(Any::null())),
        Rs512 => ("1.2.840.113549.1.1.13", Some(Any::null())),
        Ed25519 => ("1.3.101.112", None),
        Ed448 => ("1.3.101.113", None),
        Ps256 | Ps384 | Ps512 => {
            let (hash, salt) = match algorithm {
                Ps256 => (SHA256, 32),
                Ps384 => (SHA384, 48),
                _ => (SHA512, 64),
            };
            let hash = AlgorithmIdentifier {
                oid: hash,
                parameters: Some(Any::null()),
            };
            let params = PssParameters {
                mask: Some(AlgorithmIdentifier {
                    oid: MGF1,
                    parameters: Some(Any::encode_from(&hash)?),
                }),
                hash: Some(hash),
                salt: Some(salt),
                trailer: None,
            };
            return Ok(AlgorithmIdentifier {
                oid: RSA_PSS,
                parameters: Some(Any::encode_from(&params)?),
            }
            .to_der()?);
        }
    };
    Ok(AlgorithmIdentifier {
        oid: ObjectIdentifier::new(oid)?,
        parameters,
    }
    .to_der()?)
}
