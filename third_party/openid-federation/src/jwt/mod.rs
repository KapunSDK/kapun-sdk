/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/


use std::{
    fmt::Debug,
    marker::PhantomData,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use josekit::{
    JoseHeader,
    jws::{JwsHeader, JwsVerifier},
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::instrument;

use crate::models::{
    JwkSet,
    errors::{FederationError, JwsError},
    transformer::Value,
};

pub mod jwt_rfc7519 {
    use crate::models;
    models!(
        #[derive(Default)]
        pub struct TimeValidity {
            #[serde(alias = "nbf")]
            not_before: Option<u64>,
            #[serde(alias = "exp")]
            expires_at: Option<u64>,
            #[serde(alias = "iat")]
            issued_at: Option<u64>,
        }
    );
    models!(
        #[derive(Default)]
        pub struct Header {
            kid: String,
            typ: String,
        }
    );
}

pub trait JwtVerifier<T: Serialize + DeserializeOwned + Debug> {
    fn verify_header(&self, jwt: &Jwt<T>) -> Result<(), FederationError>;
    fn verify_time(&self, jwt: &Jwt<T>) -> Result<(), FederationError> {
        self.verify_time_at(
            jwt,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }
    #[instrument(skip(self, jwt), fields(time_parts))]
    fn verify_time_at(&self, jwt: &Jwt<T>, time: u64) -> Result<(), FederationError> {
        let val: Value = serde_json::to_value(jwt.payload_unverified().insecure())
            .unwrap()
            .into();
        let mut time_parts = jwt_rfc7519::TimeValidity::default();
        val.write_to_transformer(&mut time_parts);
        if let Some(nbf) = time_parts.not_before {
            if nbf > time {
                return Err(FederationError::Jws(JwsError::NotYetValid(
                    "JWT not yet valid".to_string(),
                )));
            }
        }
        if let Some(exp) = time_parts.expires_at {
            if exp < time {
                return Err(FederationError::Jws(JwsError::Expired(
                    "JWT expired".to_string(),
                )));
            }
        }
        Ok(())
    }
    fn verify_body(&self, jwt: &Jwt<T>) -> Result<(), FederationError>;
}

pub trait Jwtable: Serialize + DeserializeOwned + Debug {}

#[derive(Clone, Debug)]
pub struct Jwt<T: Serialize + DeserializeOwned + Debug> {
    payload: T,
    pub original_payload: String,
    pub signatures: Vec<Signature>,
}
#[derive(Clone, Debug)]
pub struct Signature {
    pub signature: String,
    pub protected: String,
    pub header: Option<String>,
}

impl<T: Serialize + DeserializeOwned + Debug> Jwt<T> {
    pub fn header(&self) -> Result<Box<dyn JoseHeader>, FederationError> {
        josekit::jwt::decode_header(self.jwt_at(0))
            .map_err(|e| FederationError::Jws(JwsError::InvalidHeader(format!("{e}"))))
    }
    pub fn payload(&self, jwk_set: &JwkSet) -> Result<&T, FederationError> {
        self.verify_signature(jwk_set)?;
        Ok(&self.payload)
    }
    pub fn payload_with_verifier(&self, verifier: &dyn JwsVerifier) -> Result<&T, FederationError> {
        self.verify_signature_with_verifier(verifier)?;
        Ok(&self.payload)
    }
    #[instrument(skip(self, jwk_set), err)]
    pub fn verify_signature(&self, jwk_set: &JwkSet) -> Result<(), FederationError> {
        let header = josekit::jwt::decode_header(self.jwt_at(0))
            .map_err(|e| FederationError::Jws(JwsError::InvalidHeader(format!("{e}"))))?;
        let Some(verifier) = jwk_set.verifier_for(header.claim("kid").unwrap().as_str().unwrap())
        else {
            return Err(FederationError::Jws(JwsError::KeyNotFound(
                "No matching key found".to_string(),
            )));
        };
        for s in &self.signatures {
            let sig_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(&s.signature)
                .map_err(|e| JwsError::EncodingError(format!("{e}")))?;
            println!("alg: {}", verifier.algorithm().name());

            verifier
                .verify(
                    format!("{}.{}", s.protected, self.original_payload).as_bytes(),
                    sig_bytes.as_slice(),
                )
                .map_err(|e| JwsError::InvalidSignature(format!("{e}")))?;
        }
        Ok(())
    }
    #[instrument(skip(self, verifier), err)]
    pub fn verify_signature_with_verifier(
        &self,
        verifier: &dyn JwsVerifier,
    ) -> Result<(), FederationError> {
        let header = josekit::jwt::decode_header(self.jwt_at(0))
            .map_err(|e| FederationError::Jws(JwsError::InvalidHeader(format!("{e}"))))?;
        if verifier.algorithm().name()
            != header
                .as_any()
                .downcast_ref::<JwsHeader>()
                .unwrap()
                .algorithm()
                .unwrap()
        {
            return Err(JwsError::InvalidHeader("algorithm not matching".to_string()).into());
        }
        for s in &self.signatures {
            let sig_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(&s.signature)
                .map_err(|e| JwsError::EncodingError(format!("{e}")))?;
            println!("alg: {}", verifier.algorithm().name());

            verifier
                .verify(
                    format!("{}.{}", s.protected, self.original_payload).as_bytes(),
                    sig_bytes.as_slice(),
                )
                .map_err(|e| JwsError::InvalidSignature(format!("{e}")))?;
        }
        Ok(())
    }
    pub fn verify(&self, verifier: &dyn JwtVerifier<T>) -> Result<(), FederationError> {
        verifier.verify_header(self)?;
        verifier.verify_time(self)?;
        verifier.verify_body(self)?;
        Ok(())
    }
    pub fn payload_unverified(&self) -> Unverified<&T> {
        let p = &self.payload;
        Unverified::new(p)
    }
    pub fn jwt_at(&self, index: usize) -> String {
        let sig = self.signatures.get(index).unwrap();
        format!(
            "{}.{}.{}",
            sig.protected, self.original_payload, sig.signature
        )
    }
}
pub struct Unverified<'a, T> {
    payload: T,
    _data: PhantomData<&'a T>,
}
impl<'a, T> Unverified<'a, &'a T> {
    pub fn new(payload: &'a T) -> Self {
        Self {
            payload,
            _data: PhantomData,
        }
    }
    pub fn insecure(&self) -> &T {
        self.payload
    }
}

impl<T: Debug> FromStr for Jwt<T>
where
    T: Serialize + DeserializeOwned,
{
    type Err = FederationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let binding = s.split('.').collect::<Vec<_>>();
        let [header, payload, signature] = binding.as_slice() else {
            return Err(JwsError::InvalidFormat("Invalid JWT format".to_string()).into());
        };
        let original_payload = payload.to_string();
        let payload = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let payload = std::str::from_utf8(&payload).unwrap();
        Ok(Self {
            payload: serde_json::from_str(payload)
                .map_err(|e| JwsError::BodyParseError(format!("{e}")))?,
            original_payload,
            signatures: vec![Signature {
                signature: signature.to_string(),
                protected: header.to_string(),
                header: None,
            }],
        })
    }
}

impl JwkSet {
    pub fn verifier_for(&self, key_id: &str) -> Option<Box<dyn JwsVerifier>> {
        let jwks = self.0.get(key_id);
        for jwk in jwks {
            for alg in [
                josekit::jws::ES256,
                josekit::jws::ES384,
                josekit::jws::ES512,
            ] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
            for alg in [
                josekit::jws::RS256,
                josekit::jws::RS384,
                josekit::jws::RS512,
            ] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
            for alg in [
                josekit::jws::PS256,
                josekit::jws::PS384,
                josekit::jws::PS512,
            ] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
            for alg in [josekit::jws::EdDSA] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{EntityStatement, transformer::Value};

    #[test]
    fn test_signature_verify() {
        let trust_chain: Value = serde_json::from_str(include_str!(
            "../../test_resources/figure_6_trust_chain.json"
        ))
        .unwrap();
        let trust_chain = trust_chain.as_array().unwrap();
        let mut jwts = vec![];
        for t in trust_chain {
            let jwt = t
                .as_str()
                .unwrap()
                .parse::<crate::jwt::Jwt<EntityStatement>>()
                .unwrap();
            jwts.push(jwt);
        }
        for i in 0..jwts.len() {
            let jwt = &jwts[i];
            let p = jwt.payload_unverified();
            if let Some(authority_hints) = p.insecure().authority_hints.as_ref() {
                println!("{authority_hints:?}");
            }
            if i == jwts.len() - 1 {
                let jwks = &p.insecure().jwks;
                println!("verified: {:?}", jwt.verify_signature(jwks));
            } else {
                let parent_jwt = jwts[i + 1].payload_unverified();
                let jwks = &parent_jwt.insecure().jwks;
                println!("verified: {:?}", jwt.verify_signature(jwks));
            }
        }
    }
}
