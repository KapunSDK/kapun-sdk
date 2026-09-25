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

use heidi_jwt::{
    jwt::{Jwt, JwtVerifier},
    models::errors::{JwsError, JwtError, PayloadError},
};
use tracing::instrument;

use crate::models::{EntityConfig, EntityStatement};
use serde_json::Value as JsonValue;

const ENTITY_STATEMENT_TYPE: &str = "entity-statement+jwt";
const TYP_CLAIM: &str = "typ";

impl JwtVerifier<EntityStatement> for EntityStatement {
    #[instrument(skip(self, jwt), err)]
    fn verify_header(&self, jwt: &Jwt<EntityStatement>) -> Result<(), JwtError> {
        let header = jwt.header()?;
        let Some(typ) = header.claim(TYP_CLAIM) else {
            return Err(JwtError::Jws(JwsError::TypeError(
                "typ claim not found".to_string(),
            )));
        };
        let JsonValue::String(typ) = typ else {
            return Err(JwtError::Jws(JwsError::TypeError(
                "typ claim is not a string".to_string(),
            )));
        };
        if typ != ENTITY_STATEMENT_TYPE {
            return Err(JwtError::Jws(JwsError::TypeError(
                "typ claim is not 'entity-statement+jwt'".to_string(),
            )));
        }
        let Some(typ) = header.claim("kid") else {
            return Err(JwtError::Jws(JwsError::InvalidHeader(
                "kid claim not found".to_string(),
            )));
        };
        let JsonValue::String(_) = typ else {
            return Err(JwtError::Jws(JwsError::TypeError(
                "kid claim is not a string".to_string(),
            )));
        };
        Ok(())
    }
    #[instrument(skip(self, jwt), err)]
    fn verify_body(&self, jwt: &Jwt<EntityStatement>) -> Result<(), JwtError> {
        let unverified = jwt.payload_unverified();
        if unverified.insecure().authority_hints().is_some() {
            return Err(PayloadError::MissingRequiredProperty(
                "authority_hints should be none".to_string(),
            )
            .into());
        }
        if unverified.insecure().iss() == unverified.insecure().sub() {
            return Err(JwtError::Payload(PayloadError::InvalidPayload(
                "iss and sub claims should be different if not an entity configuration".to_string(),
            )));
        }
        Ok(())
    }
}

impl JwtVerifier<EntityStatement> for EntityConfig {
    #[instrument(skip(self, jwt), err)]
    fn verify_header(&self, jwt: &Jwt<EntityStatement>) -> Result<(), JwtError> {
        let header = jwt.header()?;
        let Some(typ) = header.claim(TYP_CLAIM) else {
            return Err(JwsError::TypeError("typ claim not found".to_string()).into());
        };
        let JsonValue::String(typ) = typ else {
            return Err(JwsError::TypeError("typ claim is not a string".to_string()).into());
        };
        if typ != ENTITY_STATEMENT_TYPE {
            return Err(
                JwsError::TypeError("typ claim is not 'entity-statement+jwt'".to_string()).into(),
            );
        }
        let Some(typ) = header.claim("kid") else {
            return Err(JwsError::InvalidHeader("kid claim not found".to_string()).into());
        };
        let JsonValue::String(_) = typ else {
            return Err(JwsError::InvalidHeader("kid claim is not a string".to_string()).into());
        };
        Ok(())
    }
    #[instrument(skip(self, jwt), err)]
    fn verify_body(&self, jwt: &Jwt<EntityStatement>) -> Result<(), JwtError> {
        let unverified = jwt.payload_unverified();
        if unverified.insecure().authority_hints().is_none()
            && !matches!(self, EntityConfig::TrustAnchor(_))
        {
            return Err(PayloadError::MissingRequiredProperty(
                "authority_hints claim not found".to_string(),
            )
            .into());
        }
        if unverified.insecure().iss() != unverified.insecure().sub() {
            return Err(JwtError::Payload(PayloadError::InvalidPayload(
                "iss and sub claims do not match".to_string(),
            )));
        }
        Ok(())
    }
}
