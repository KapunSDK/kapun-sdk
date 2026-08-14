/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use crate::crypto::{base64_url_decode, SignatureCreator};
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair as JoseKeyPair};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::{ecdsa::signature::Verifier, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;
use serde_json::Value;
use std::sync::Arc;

pub enum KeyType {
    P256,
}
#[derive(Debug, Clone)]
pub enum KeyPair {
    P256 {
        private_key: p256::SecretKey,
        public_key: p256::PublicKey,
        key_id: Option<String>,
    },
}

pub fn generate_keypair() -> KeyPair {
    let private_key = p256::SecretKey::random(&mut OsRng);
    let public_key = private_key.public_key();
    KeyPair::P256 {
        private_key,
        public_key,
        key_id: None,
    }
}
pub fn from_private_key(private_key: Vec<u8>) -> Option<KeyPair> {
    let private_key = p256::SecretKey::from_slice(&private_key).ok()?;
    let public_key = private_key.public_key();
    Some(KeyPair::P256 {
        private_key,
        public_key,
        key_id: None,
    })
}
pub fn from_private_jwk_string(private_key_jwk: &str) -> Option<KeyPair> {
    let jwk = Jwk::from_bytes(private_key_jwk.as_bytes()).ok()?;
    let jose_key_pair = EcKeyPair::from_jwk(&jwk).ok()?;
    let private_key = p256::SecretKey::from_sec1_der(&jose_key_pair.to_raw_private_key()).ok()?;
    let public_key = private_key.public_key();
    let key_id = jwk
        .key_id()
        .filter(|kid| !kid.is_empty())
        .map(str::to_string);
    Some(KeyPair::P256 {
        private_key,
        public_key,
        key_id,
    })
}

impl KeyPair {
    pub fn with_key_id(&self, key_id: String) -> Self {
        match self {
            Self::P256 {
                private_key,
                public_key,
                ..
            } => Self::P256 {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                key_id: Some(key_id),
            },
        }
    }

    pub fn sign_with_key(&self, message: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        match self {
            Self::P256 { private_key, .. } => {
                let signing_key: SigningKey = private_key.into();
                let signature: Signature = signing_key.sign(&message);
                Ok(signature.to_vec())
            }
        }
    }
    pub fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyPair::P256 {
                private_key,
                public_key: _,
                key_id: _,
            } => private_key.to_bytes().to_vec(),
        }
    }
    pub fn public_key_sec1(&self) -> Vec<u8> {
        match self {
            Self::P256 {
                private_key: _,
                public_key,
                key_id: _,
            } => public_key.to_sec1_bytes().to_vec(),
        }
    }

    pub fn public_key_compressed(&self) -> Vec<u8> {
        match self {
            Self::P256 {
                private_key: _,
                public_key,
                key_id: _,
            } => public_key.to_encoded_point(true).as_bytes().to_vec(),
        }
    }

    pub fn jwk_string(&self) -> String {
        self.to_jose_key_pair()
            .map(|key_pair| key_pair.to_jwk_public_key().to_string())
            .unwrap_or_default()
    }
    pub fn jwk_string_with_key_id(&self, key_id: &str) -> String {
        let mut jwk: Value = serde_json::from_str(&self.jwk_string()).unwrap_or(Value::Null);
        if let Some(jwk) = jwk.as_object_mut() {
            jwk.insert("kid".to_string(), Value::String(key_id.to_string()));
        }
        serde_json::to_string(&jwk).unwrap_or_else(|_| self.jwk_string())
    }
    pub fn private_jwk_string(&self) -> String {
        self.to_jose_key_pair()
            .map(|key_pair| key_pair.to_jwk_private_key().to_string())
            .unwrap_or_default()
    }

    fn to_jose_key_pair(&self) -> Option<EcKeyPair> {
        let mut key_pair =
            EcKeyPair::from_der(self.private_key_bytes(), Some(EcCurve::P256)).ok()?;
        let Self::P256 { key_id, .. } = self;
        if let Some(key_id) = key_id {
            key_pair.set_key_id(Some(key_id.clone()));
        }
        Some(key_pair)
    }
}

use crate::SigningError;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SoftwareKeyPair(KeyPair);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct VerificationKey(VerifyingKey);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl VerificationKey {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_coords(x: String, y: String) -> Self {
        let x_bytes = base64_url_decode(x);
        let y_bytes = base64_url_decode(y);
        let mut key_bytes = vec![0x04];
        key_bytes.extend_from_slice(x_bytes.as_slice());
        key_bytes.extend_from_slice(y_bytes.as_slice());
        let vp: VerifyingKey = VerifyingKey::from_sec1_bytes(&key_bytes).unwrap();
        Self(vp)
    }

    fn verify(self: Arc<Self>, signature: Vec<u8>, data: Vec<u8>) -> bool {
        let sig = if let Ok(sig) = Signature::from_slice(&signature) {
            println!("normal");
            sig
        } else if let Ok(sig) = Signature::from_der(&signature) {
            println!("from der");
            sig
        } else {
            return false;
        };
        self.0.verify(&data, &sig).map(|_| true).unwrap_or(false)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SoftwareKeyPair {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Self {
        Self(generate_keypair())
    }
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new_with_key_id(key_id: String) -> Self {
        Self(generate_keypair().with_key_id(key_id))
    }
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_private_key(private_key: Vec<u8>) -> Arc<Self> {
        Arc::new(Self(
            from_private_key(private_key).unwrap_or(generate_keypair()),
        ))
    }
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_jwk_string(jwk_string: &str) -> Arc<Self> {
        Arc::new(Self(
            from_private_jwk_string(jwk_string).unwrap_or(generate_keypair()),
        ))
    }

    pub fn sign_with_key(&self, message: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        self.0.sign_with_key(message)
    }
    pub fn jwk_string(&self) -> String {
        self.0.jwk_string()
    }
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.0.public_key_sec1()
    }
    pub fn public_key_compressed(&self) -> Vec<u8> {
        self.0.public_key_compressed()
    }
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.0.private_key_bytes()
    }
    pub fn private_jwk_string(&self) -> String {
        self.0.private_jwk_string()
    }
    pub fn as_signature_creator(self: Arc<Self>) -> Arc<dyn SignatureCreator> {
        self.clone()
    }
}

impl SignatureCreator for SoftwareKeyPair {
    fn alg(&self) -> String {
        match self.0 {
            KeyPair::P256 { .. } => String::from("ES256"),
        }
    }

    fn sign(&self, bytes: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        self.0.sign_with_key(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn public_jwk_omits_key_id_by_default() {
        let key_pair = SoftwareKeyPair::new();
        let bare_jwk: Value = serde_json::from_str(&key_pair.jwk_string()).unwrap();

        assert_eq!(bare_jwk.get("kid"), None);
    }

    #[test]
    fn generated_key_with_key_id_serializes_key_id() {
        let key_pair = SoftwareKeyPair::new_with_key_id("issuer-key".to_string());
        let public_jwk: Value = serde_json::from_str(&key_pair.jwk_string()).unwrap();
        let private_jwk: Value = serde_json::from_str(&key_pair.private_jwk_string()).unwrap();

        assert_eq!(
            public_jwk.get("kid").and_then(Value::as_str),
            Some("issuer-key")
        );
        assert_eq!(
            private_jwk.get("kid").and_then(Value::as_str),
            Some("issuer-key")
        );
    }

    #[test]
    fn imported_key_with_key_id_serializes_key_id() {
        let key_pair = SoftwareKeyPair::new_with_key_id("issuer-key".to_string());
        let imported = SoftwareKeyPair::from_jwk_string(&key_pair.private_jwk_string());
        let public_jwk: Value = serde_json::from_str(&imported.jwk_string()).unwrap();

        assert_eq!(
            public_jwk.get("kid").and_then(Value::as_str),
            Some("issuer-key")
        );
    }
}

// impl NativeSigner for SoftwareKeyPair {
//     fn key_reference(&self) -> Vec<u8> {
//         let id: [u8; 32] = rand::random();
//         id.to_vec()
//     }
//
//     fn sign(&self, msg: String) -> Result<Vec<u8>, SigningError> {
//         self.sign_bytes(msg.as_bytes().to_vec())
//     }
//
//     fn sign_bytes(&self, msg: Vec<u8>) -> Result<Vec<u8>, SigningError> {
//         self.0
//             .sign_with_key(msg)
//             .map_err(|_| SigningError::FailedToSign)
//     }
//
//     fn public_key(&self) -> Vec<u8> {
//         self.0.public_key_sec1()
//     }
//
//     fn key_id(&self) -> String {
//         let digest = Sha256::digest(&self.0.public_key_sec1()).to_vec();
//         base64::prelude::BASE64_STANDARD_NO_PAD.encode(&digest)
//     }
//
//     fn jwt_header(&self) -> String {
//         let jwk = self.public_key_jwk();
//         let output =
//             format!("{{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\",\"jwk\" : {jwk} }}");
//         output
//     }
//
//     fn alg(&self) -> String {
//         String::from("ES256")
//     }
//
//     fn public_key_jwk(&self) -> String {
//         self.0.jwk_string()
//     }
//
//     fn private_key(&self) -> Result<Vec<u8>, SigningError> {
//         Ok(self.0.private_key_bytes())
//     }
//
//     fn private_key_exportable(&self) -> bool {
//         true
//     }
//
//     fn key_attestation(&self) -> Option<String> {
//         None
//     }
// }
