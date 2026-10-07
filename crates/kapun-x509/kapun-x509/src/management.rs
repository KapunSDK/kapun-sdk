// SPDX-FileCopyrightText: 2026 Ubique Innovation AG and Heidi contributors
// SPDX-License-Identifier: Apache-2.0

//! Owned X.509 APIs for applications using external signing providers.
mod construction;
mod csr;
mod inspection;
mod validation;

pub use crate::crypto::{
    SignatureAlgorithm, SignatureEncoding, signature_algorithm,
    verify_signed_data as verify_signature,
};
pub use construction::*;
pub use csr::*;
pub use inspection::*;
pub use validation::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid DER: {0}")]
    Der(#[from] der::Error),
    #[error("Invalid OID: {0}")]
    Oid(#[from] const_oid::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("Unsupported signature algorithm or parameters")]
    UnsupportedAlgorithm,
    #[error("Invalid certificate signature or public key")]
    InvalidSignature,
    #[error(transparent)]
    Validation(#[from] crate::x509::ValidationError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<crate::crypto::SignatureError> for Error {
    fn from(error: crate::crypto::SignatureError) -> Self {
        match error {
            crate::crypto::SignatureError::UnknownAlgorithm
            | crate::crypto::SignatureError::UnsupportedSignatureAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            _ => Self::InvalidSignature,
        }
    }
}
