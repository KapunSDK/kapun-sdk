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

pub mod errors;
pub mod transformer;
pub mod trust_chain;
pub mod verifiers;

use std::collections::HashMap;

use heidi_jwt::{
    jwt::{Jwt, Unverified, verifier::DefaultVerifier},
    models::JwkSet,
};
use serde_json::Value as JsonValue;
use tracing::instrument;

use crate::{
    DefaultConfig, FetchConfig, fetch_jwt, fetch_jwt_async,
    models::{
        errors::{FederationError, JwsError, TrustChainError},
        transformer::Value,
    },
};

#[derive(Debug, Clone)]
pub enum EntityConfig {
    Leaf(Jwt<EntityStatement>),
    Intermediate(Jwt<EntityStatement>),
    TrustAnchor(Jwt<EntityStatement>),
}
impl EntityConfig {
    pub fn payload_unverified<'a>(&self) -> Unverified<'a, &EntityStatement> {
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => jwt.payload_unverified(),
        }
    }
    pub fn metadata(&self) -> Option<HashMap<String, Value>> {
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => {
                let unverified = jwt.payload_unverified();
                unverified.insecure().metadata.clone()
            }
        }
    }
    pub fn metadata_policy(&self) -> Option<HashMap<String, Value>> {
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => {
                let unverified = jwt.payload_unverified();
                unverified.insecure().metadata_policy.clone()
            }
        }
    }

    pub fn jwks(&self) -> JwkSet {
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => {
                let unverified = jwt.payload_unverified();
                unverified.insecure().jwks.clone()
            }
        }
    }
    pub fn sub(&self) -> String {
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => {
                let unverified = jwt.payload_unverified();
                unverified.insecure().sub.clone()
            }
        }
    }
    #[instrument(skip(self), err)]
    pub fn verify(&self) -> Result<(), FederationError> {
        // verify signature
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => {
                jwt.verify_signature(&jwt.payload_unverified().insecure().jwks)
            }
        }
        .map_err(|e| FederationError::Jws(JwsError::InvalidSignature(format!("{e}"))))?;
        // verify jwt payload
        match self {
            EntityConfig::Intermediate(jwt)
            | EntityConfig::Leaf(jwt)
            | EntityConfig::TrustAnchor(jwt) => jwt
                .verify(self)
                .map_err(|e| FederationError::Jws(JwsError::InvalidFormat(format!("{e}"))))?,
        };
        Ok(())
    }

    #[instrument(skip(self), err)]
    pub async fn fetch_subordinate_async(
        &self,
        sub: &str,
    ) -> Result<Jwt<EntityStatement>, FederationError> {
        self.fetch_subordinate_async_with_config::<DefaultConfig>(sub)
            .await
    }

    #[instrument(skip(self), err)]
    pub async fn fetch_subordinate_async_with_config<Config: FetchConfig>(
        &self,
        sub: &str,
    ) -> Result<Jwt<EntityStatement>, FederationError> {
        match self {
            EntityConfig::Leaf(_) => Err(TrustChainError::LeafCannotHaveSubordinate(
                "Leaf entities cannot have subordinates".to_string(),
            )
            .into()),
            EntityConfig::Intermediate(jwt) | EntityConfig::TrustAnchor(jwt) => {
                let es = jwt.payload_unverified();
                let es = jwt
                    .payload(
                        &es.insecure().jwks,
                        &DefaultVerifier::new("entity-statement+jwt".to_string(), vec![]),
                    )
                    .map_err(|e| FederationError::Jws(JwsError::BodyParseError(format!("{e}"))))?;
                let Some(metadata) = es.metadata.as_ref() else {
                    return Err(TrustChainError::InvalidEntityConfig(
                        "Entity Config must have metadata".to_string(),
                    )
                    .into());
                };
                let Some(federation_entity) = metadata.get("federation_entity") else {
                    return Err(TrustChainError::InvalidEntityConfig(
                        "Entity Config must have federation_entity".to_string(),
                    )
                    .into());
                };
                let mut fe = FederationEntity::default();
                federation_entity.write_to_transformer(&mut fe);
                let Some(federation_fetch_endpoint) = fe.federation_fetch_endpoint else {
                    return Err(TrustChainError::InvalidEntityConfig("Federation Entity must have federation_fetch_endpoint for non leaf entities".to_string()).into());
                };
                fetch_jwt_async::<_, Config>(&format!(
                    "{federation_fetch_endpoint}?sub={}",
                    urlencoding::encode(sub)
                ))
                .await
            }
        }
    }

    #[instrument(skip(self), err)]
    pub fn fetch_subordinate(&self, sub: &str) -> Result<Jwt<EntityStatement>, FederationError> {
        self.fetch_subordinate_with_config::<DefaultConfig>(sub)
    }

    #[instrument(skip(self), err)]
    pub fn fetch_subordinate_with_config<Config: FetchConfig>(
        &self,
        sub: &str,
    ) -> Result<Jwt<EntityStatement>, FederationError> {
        match self {
            EntityConfig::Leaf(_) => Err(TrustChainError::LeafCannotHaveSubordinate(
                "Leaf entities cannot have subordinates".to_string(),
            )
            .into()),
            EntityConfig::Intermediate(jwt) | EntityConfig::TrustAnchor(jwt) => {
                let es = jwt.payload_unverified();
                let es = jwt
                    .payload(
                        &es.insecure().jwks,
                        &DefaultVerifier::new("entity-statement+jwt".to_string(), vec![]),
                    )
                    .map_err(|e| FederationError::Jws(JwsError::BodyParseError(format!("{e}"))))?;
                let Some(metadata) = es.metadata.as_ref() else {
                    return Err(TrustChainError::InvalidEntityConfig(
                        "Entity Config must have metadata".to_string(),
                    )
                    .into());
                };
                let Some(federation_entity) = metadata.get("federation_entity") else {
                    return Err(TrustChainError::InvalidEntityConfig(
                        "Entity Config must have federation_entity".to_string(),
                    )
                    .into());
                };
                let mut fe = FederationEntity::default();
                federation_entity.write_to_transformer(&mut fe);
                let Some(federation_fetch_endpoint) = fe.federation_fetch_endpoint else {
                    return Err(TrustChainError::InvalidEntityConfig("Federation Entity must have federation_fetch_endpoint for non leaf entities".to_string()).into());
                };
                fetch_jwt::<_, Config>(&format!(
                    "{federation_fetch_endpoint}?sub={}",
                    urlencoding::encode(sub)
                ))
            }
        }
    }

    #[instrument(skip(self), err)]
    pub async fn fetch_authority_async(
        &self,
        authority: &str,
    ) -> Result<EntityConfig, FederationError> {
        self.fetch_authority_async_with_config::<DefaultConfig>(authority)
            .await
    }

    #[instrument(skip(self), err)]
    pub async fn fetch_authority_async_with_config<Config: FetchConfig>(
        &self,
        authority: &str,
    ) -> Result<EntityConfig, FederationError> {
        match self {
            EntityConfig::Leaf(_) | EntityConfig::Intermediate(_) => {
                let config = fetch_jwt_async::<EntityStatement, Config>(&format!(
                    "{authority}/.well-known/openid-federation"
                ))
                .await?;
                Ok(
                    if config
                        .payload_unverified()
                        .insecure()
                        .authority_hints
                        .is_some()
                    {
                        EntityConfig::Intermediate(config)
                    } else {
                        EntityConfig::TrustAnchor(config)
                    },
                )
            }
            EntityConfig::TrustAnchor(_) => {
                Err(TrustChainError::RootHasNoAuthority("TrustAnchor".to_string()).into())
            }
        }
    }

    #[instrument(skip(self), err)]
    pub fn fetch_authority(&self, authority: &str) -> Result<EntityConfig, FederationError> {
        self.fetch_authority_with_config::<DefaultConfig>(authority)
    }

    #[instrument(skip(self), err)]
    pub fn fetch_authority_with_config<Config: FetchConfig>(
        &self,
        authority: &str,
    ) -> Result<EntityConfig, FederationError> {
        match self {
            EntityConfig::Leaf(_) | EntityConfig::Intermediate(_) => {
                let config = fetch_jwt::<EntityStatement, Config>(&format!(
                    "{authority}/.well-known/openid-federation"
                ))?;
                Ok(
                    if config
                        .payload_unverified()
                        .insecure()
                        .authority_hints
                        .is_some()
                    {
                        EntityConfig::Intermediate(config)
                    } else {
                        EntityConfig::TrustAnchor(config)
                    },
                )
            }
            EntityConfig::TrustAnchor(_) => {
                Err(TrustChainError::RootHasNoAuthority("TrustAnchor".to_string()).into())
            }
        }
    }
}

impl EntityConfig {
    pub fn load_from_url<Config: FetchConfig>(url: &str) -> Result<Self, FederationError> {
        let new_statement =
            fetch_jwt::<_, Config>(&format!("{url}/.well-known/openid-federation",))?;
        Ok(Self::Leaf(new_statement))
    }
    async fn load_from_url_async<Config: FetchConfig>(url: &str) -> Result<Self, FederationError> {
        let new_statement =
            fetch_jwt_async::<_, Config>(&format!("{url}/.well-known/openid-federation",)).await?;
        Ok(Self::Leaf(new_statement))
    }
    pub fn refresh<Config: FetchConfig>(&mut self) -> Result<(), FederationError> {
        match self {
            EntityConfig::Leaf(jwt)
            | EntityConfig::Intermediate(jwt)
            | EntityConfig::TrustAnchor(jwt) => {
                let new_statement = fetch_jwt::<_, Config>(&format!(
                    "{}/.well-known/openid-federation",
                    jwt.payload_unverified().insecure().sub()
                ))?;
                *self = EntityConfig::TrustAnchor(new_statement);
            }
        }
        Ok(())
    }
    pub fn new_leaf(entity_statement: Jwt<EntityStatement>) -> Option<Self> {
        entity_statement
            .payload_unverified()
            .insecure()
            .authority_hints
            .as_ref()?;
        Some(EntityConfig::Leaf(entity_statement))
    }
    pub fn new_intermediate(entity_statement: Jwt<EntityStatement>) -> Option<Self> {
        entity_statement
            .payload_unverified()
            .insecure()
            .authority_hints
            .as_ref()?;
        Some(EntityConfig::Intermediate(entity_statement))
    }
    pub fn new_trust_anchor(entity_statement: Jwt<EntityStatement>) -> Option<Self> {
        if entity_statement
            .payload_unverified()
            .insecure()
            .authority_hints
            .is_some()
        {
            return None;
        }
        Some(EntityConfig::TrustAnchor(entity_statement))
    }
}

crate::models!(
    #[derive(Debug, Clone, Default)]
    pub struct EntityStatement {
        iss: String,
        sub: String,
        iat: u64,
        exp: u64,
        jwks: JwkSet,
        #[serde(skip_serializing_if = "Option::is_none")]
        authority_hints: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, transformer::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_policy: Option<HashMap<String, transformer::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        constraints: Option<transformer::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crit: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_policy_crit: Option<transformer::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        trust_marks: Option<Vec<TrustMark>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        trust_mark_issuers: Option<transformer::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        trust_mark_owners: Option<TrustMarkOwner>,
        #[serde(skip_serializing_if = "Option::is_none")]
        trust_mark_owners_crit: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_endpoint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        trust_anchor: Option<String>,
    }
);
crate::models!(
    #[derive(Debug, Clone)]
    pub struct TrustMark {
        trust_mark_type: String,
        trust_mark: String,
    }
);
crate::models!(
    #[derive(Debug, Clone)]
    pub struct TrustMarkOwner {
        sub: String,
        jwks: JwkSet,
    }
);
crate::models!(
    #[derive(Debug, Clone, Default)]
    pub struct FederationEntity {
        federation_fetch_endpoint: Option<String>,
        federation_list_endpoint: Option<String>,
    }
);

// #[derive(Deserialize, Serialize, Debug, Clone)]
// pub struct JwkSet(
//     #[serde(serialize_with = "JwkSet::serialize_to_string")]
//     #[serde(deserialize_with = "JwkSet::deserialize")]
//     pub JoseJwkSet,
// );

// impl JwkSet {
//     fn serialize_to_string<S>(set: &JoseJwkSet, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let set: &serde_json::Map<String, serde_json::Value> = set.as_ref();
//         serializer.serialize_some(set)
//     }
//     fn deserialize<'de, D>(deserializer: D) -> Result<JoseJwkSet, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let set: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
//         let Ok(set) = serde_json::from_value(set) else {
//             return Err(serde::de::Error::custom("Failed to deserialize JWK set"));
//         };
//         let Ok(set) = JoseJwkSet::from_map(set) else {
//             return Err(serde::de::Error::custom("Failed to deserialize JWK set"));
//         };
//         Ok(set)
//     }
// }

crate::extension!([jti: String], EntityStatement);

#[macro_export]
macro_rules! extension {
    ([$($field:ident: $type:ty),*], $struct:ty) => {
        impl $struct {
            $(
                pub fn $field(&self) -> $type {
                    let value = self.additional_fields.get(stringify!($field)).unwrap_or(&JsonValue::Null);
                    serde_json::from_value(value.to_owned()).unwrap()
                }
            )*
        }
    };
}

#[macro_export]
macro_rules! models {
    ($(#[$($meta:tt)*])* $vis:vis struct $name:ident { $( $(#[$($meta_field:tt)*])* $field:ident : $type:ty),*, }) => {
        #[derive(serde::Deserialize, serde::Serialize)]
        $(#[$($meta)*])*
        $vis struct $name {
            $($(#[$($meta_field)*])* pub $field: $type),*,
            #[serde(flatten)]
            pub additional_fields: serde_json::Map<String, serde_json::Value>,
        }
        paste::paste! {
            pub struct [<$name Builder>] {
                 $($field: Option<$type>,)*
            }

            impl [<$name Builder>] {
                pub fn new() -> Self {
                    [<$name Builder>] {
                        $($field: None,)*
                    }
                }

                $(
                    pub fn $field(mut self, $field: $type) -> Self {
                        self.$field = Some($field);
                        self
                    }
                )*

                pub fn build(self) -> $name {
                    $name {
                        $($field: self.$field.unwrap_or_default(),)*
                        additional_fields: serde_json::Map::new(),
                    }
                }
            }
        }
        impl $name {
            $(
                pub fn $field(&self) -> $type {
                    self.$field.clone()
                }
            )*
            pub fn get_field(&self, name: &str) -> serde_json::Value {
                match name {
                    $(stringify!($field) => {
                       serde_json::to_value(&self.$field).unwrap_or(serde_json::Value ::Null)
                    } )*
                    _ => self.additional_fields.get(name).unwrap_or(&serde_json::Value ::Null).to_owned()
                }
            }
            pub fn to_transformer(&self, transformer: &mut dyn $crate::models::transformer::Transformer) {
                $(
                    let v = serde_json::to_value(&self.$field).unwrap_or(serde_json::Value ::Null);
                    transformer.set_field(stringify!($field), v.into());
                )*
                for (key, value) in &self.additional_fields {
                    transformer.set_field(key, value.clone().into());
                }
            }
        }
        impl $crate::models::transformer::Transformer for $name {
            fn set_field(&mut self, name: &str, value: $crate::models::transformer::Value) {
                match name {
                    $(stringify!($field) => {
                        self.$field = serde_json::from_value(value.into()).unwrap();
                    } )*
                    _ =>  { self.additional_fields.insert(name.to_string(), value.into()); }
                }
            }
            fn transform(self, transformer: &mut dyn $crate::models::transformer::Transformer) -> Result<(), String> {
                self.to_transformer(transformer);
                Ok(())
            }
        }
    };
}

#[cfg(test)]
mod tests {

    use super::JwkSet;

    use crate::models::{
        EntityStatement,
        transformer::{Transformer, Value},
    };
    #[test]
    fn test_parsing_entity_statement() {
        let es = include_str!("../../test_resources/figure_2_example_entity_statement.json");
        let es: EntityStatement = serde_json::from_str(es).unwrap();
        println!("{:#?}", es);
        let jti = es.get_field("jti");
        assert_eq!(
            jti,
            serde_json::Value::String(String::from("7l2lncFdY6SlhNia"))
        );
        let jti = es.jti();
        assert_eq!(jti, String::from("7l2lncFdY6SlhNia"));
    }
    #[test]
    fn test_transformer() {
        let es = include_str!("../../test_resources/figure_2_example_entity_statement.json");
        let es: EntityStatement = serde_json::from_str(es).unwrap();
        #[derive(Debug)]
        struct EntityConfiguration {
            iss: String,
            sub: String,
            iat: u64,
            exp: u64,
            jwks: JwkSet,
            authority_hints: Option<Vec<String>>,
            metadata: Option<Value>,
            metadata_policy: Option<Value>,
        }
        impl Transformer for EntityConfiguration {
            fn set_field(&mut self, name: &str, value: super::transformer::Value) {
                println!("{}: {:?}", name, value);
                match name {
                    "iss" => self.iss = value.as_str().unwrap().to_string(),
                    "sub" => self.sub = value.as_str().unwrap().to_string(),
                    "iat" => self.iat = value.as_u64().unwrap(),
                    "exp" => self.exp = value.as_u64().unwrap(),
                    "jwks" => self.jwks = JwkSet::default(),
                    "authority_hints" => self.authority_hints = value.into_typed_array(),
                    "metadata" => self.metadata = value.into(),
                    "metadata_policy" => self.metadata_policy = value.into(),
                    _ => {}
                }
            }
            fn transform(self, _transformer: &mut dyn Transformer) -> Result<(), String> {
                todo! {}
            }
        }
        let mut transformer = EntityConfiguration {
            iss: String::from("example.com"),
            sub: String::from("example.com"),
            iat: 1630456800,
            exp: 1630456800,
            jwks: JwkSet::default(),
            authority_hints: None,
            metadata: None,
            metadata_policy: None,
        };
        es.to_transformer(&mut transformer);
        println!("{:?}", transformer);
    }
    #[test]
    fn test_transformer_value() {
        let es = include_str!("../../test_resources/figure_2_example_entity_statement.json");
        let es: serde_json::Value = serde_json::from_str(es).unwrap();
        let es: crate::models::transformer::Value = es.into();
        #[derive(Debug)]
        struct EntityConfiguration {
            iss: String,
            sub: String,
            iat: u64,
            exp: u64,
            jwks: JwkSet,
            authority_hints: Option<Vec<String>>,
            metadata: Option<Value>,
            metadata_policy: Option<Value>,
        }
        impl Transformer for EntityConfiguration {
            fn set_field(&mut self, name: &str, value: super::transformer::Value) {
                println!("{}: {:?}", name, value);
                match name {
                    "iss" => self.iss = value.as_str().unwrap().to_string(),
                    "sub" => self.sub = value.as_str().unwrap().to_string(),
                    "iat" => self.iat = value.as_u64().unwrap(),
                    "exp" => self.exp = value.as_u64().unwrap(),
                    "jwks" => self.jwks = JwkSet::default(),
                    "authority_hints" => self.authority_hints = value.into_typed_array(),
                    "metadata" => self.metadata = value.into(),
                    "metadata_policy" => self.metadata_policy = value.into(),
                    _ => {}
                }
            }

            fn transform(self, _transformer: &mut dyn Transformer) -> Result<(), String> {
                todo!()
            }
        }
        let mut transformer = EntityConfiguration {
            iss: String::from("example.com"),
            sub: String::from("example.com"),
            iat: 1630456800,
            exp: 1630456800,
            jwks: JwkSet::default(),
            authority_hints: None,
            metadata: None,
            metadata_policy: None,
        };
        es.write_to_transformer(&mut transformer);
        println!("{:?}", transformer);
    }
}
