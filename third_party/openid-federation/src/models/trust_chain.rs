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
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
};

use heidi_jwt::{JwkSet, jwt::Jwt};
use petgraph::{
    prelude::DiGraphMap,
    visit::{IntoNeighborsDirected, Reversed},
};
use sha2::{Digest, Sha256};
use tracing::{error, instrument};

use crate::{
    DefaultConfig, FetchConfig,
    models::{
        EntityConfig, EntityStatement,
        errors::{FederationError, TrustChainError},
        transformer::Value,
    },
    policy::operators::Policy,
};
pub type NodeId = [u8; 32];
pub struct TrustStore(pub Vec<TrustAnchor>);
impl TrustStore {
    pub fn is_trusted(&self, node_id: NodeId) -> bool {
        self.0.iter().any(|anchor| match anchor {
            TrustAnchor::Entity(entity) => NodeId::from(Sha256::digest(entity.sub())) == node_id,
            TrustAnchor::Subject(subject) => NodeId::from(Sha256::digest(subject)) == node_id,
        })
    }
}
pub enum TrustAnchor {
    Entity(Box<EntityConfig>),
    Subject(String),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerificationOptions {
    /// Verify the leaf entity configuration with its own JWK set instead of
    /// requiring the leaf subordinate statement to contain those keys.
    pub lenient_leaf_entity_config: bool,
}

#[derive(Debug, Clone)]
pub struct FederationRelation<Config: FetchConfig = DefaultConfig> {
    pub leaf: Entity,
    pub trust_entities: HashMap<String, Entity>,
    pub trust_anchors: Vec<String>,
    pub trust_graph: DiGraphMap<[u8; 32], EntityStatement>,
    phantom: PhantomData<Config>,
}

#[derive(Debug, Clone)]
pub struct Entity {
    pub entity_config: Option<EntityConfig>,
    pub subordinate_statement: Vec<Jwt<EntityStatement>>,
}

impl Entity {
    #[instrument(err, skip(self, trust_entities))]
    pub async fn complete_trust_async(
        &mut self,
        trust_entities: &mut HashMap<String, Entity>,
        trust_anchors: &mut Vec<String>,
        trust_graph: &mut DiGraphMap<[u8; 32], EntityStatement>,
    ) -> Result<(), FederationError> {
        self.complete_trust_async_with_config::<DefaultConfig>(
            trust_entities,
            trust_anchors,
            trust_graph,
        )
        .await
    }

    #[instrument(err, skip(self, trust_entities))]
    pub async fn complete_trust_async_with_config<Config: FetchConfig>(
        &mut self,
        trust_entities: &mut HashMap<String, Entity>,
        trust_anchors: &mut Vec<String>,
        trust_graph: &mut DiGraphMap<[u8; 32], EntityStatement>,
    ) -> Result<(), FederationError> {
        // If we have no entity config, we should already have all trust entities. Hence we can do
        // the graph building offline.
        if self.entity_config.is_none() {
            for subordinate_statement in &self.subordinate_statement {
                let iss_hash: [u8; 32] =
                    Sha256::digest(&subordinate_statement.payload_unverified().insecure().iss)
                        .into();
                let sub_hash: [u8; 32] =
                    Sha256::digest(&subordinate_statement.payload_unverified().insecure().sub)
                        .into();
                trust_graph.add_edge(
                    iss_hash,
                    sub_hash,
                    subordinate_statement
                        .payload_unverified()
                        .insecure()
                        .clone(),
                );
                let mut old_entities = trust_entities.clone();
                if let Some(iss) = trust_entities
                    .get_mut(&subordinate_statement.payload_unverified().insecure().iss)
                {
                    iss.complete_trust_with_config::<Config>(
                        &mut old_entities,
                        trust_anchors,
                        trust_graph,
                    )?;
                }
                *trust_entities = old_entities;
            }
            return Ok(());
        }

        let Some(leaf_ec) = self.entity_config.as_ref() else {
            return Err(TrustChainError::InvalidEntityConfig(
                "Leaf entity config not found".to_string(),
            )
            .into());
        };
        if leaf_ec.verify().is_err() {
            //TODO: refresh leaf
            error!("Leaf entity config verification failed");
        }

        let leaf_sub_hash: [u8; 32] = Sha256::digest(leaf_ec.sub()).into();
        trust_graph.add_edge(
            leaf_sub_hash,
            leaf_sub_hash,
            leaf_ec.payload_unverified().insecure().clone(),
        );

        let is_trust_anchor = leaf_ec
            .payload_unverified()
            .insecure()
            .authority_hints
            .is_none();
        println!(
            "{} : {:?}",
            leaf_ec.payload_unverified().insecure().iss,
            leaf_ec.payload_unverified().insecure().authority_hints
        );
        if is_trust_anchor {
            trust_anchors.push(leaf_ec.payload_unverified().insecure().iss.to_string());
        }

        // check if we have all sub statements from the authorities
        for hint in leaf_ec
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or(vec![])
        {
            if let Some(subordinate_statement) = self
                .subordinate_statement
                .iter()
                .find(|stmt| stmt.payload_unverified().insecure().iss() == hint.as_str())
            {
                let iss_hash: [u8; 32] =
                    Sha256::digest(&subordinate_statement.payload_unverified().insecure().iss)
                        .into();
                trust_graph.add_edge(
                    iss_hash,
                    leaf_sub_hash,
                    subordinate_statement
                        .payload_unverified()
                        .insecure()
                        .clone(),
                );
                let mut old_entities = trust_entities.clone();
                if let Some(iss) = trust_entities
                    .get_mut(&subordinate_statement.payload_unverified().insecure().iss)
                {
                    iss.complete_trust_with_config::<Config>(
                        &mut old_entities,
                        trust_anchors,
                        trust_graph,
                    )?;
                }
                *trust_entities = old_entities;
            } else {
                let ec = leaf_ec
                    .fetch_authority_async_with_config::<Config>(&hint)
                    .await?;
                let subordinate = ec
                    .fetch_subordinate_async_with_config::<Config>(&leaf_ec.sub())
                    .await?;
                self.subordinate_statement.push(subordinate.clone());
                // update self in trust entities
                if let Some(sub_state) =
                    trust_entities.get_mut(&subordinate.payload_unverified().insecure().sub())
                {
                    sub_state.subordinate_statement.push(subordinate.clone());
                }
                //TODO: is there a better way to handle the self referential issue of entity and completing trust?
                let entry = trust_entities.entry(ec.sub()).or_insert(Entity {
                    entity_config: None,
                    subordinate_statement: vec![],
                });

                if matches!(ec, EntityConfig::TrustAnchor(_)) {
                    trust_anchors.push(ec.sub());
                }
                entry.entity_config = Some(ec.clone());
                let mut old_entities = trust_entities.clone();

                let entry = trust_entities
                    .get_mut(&ec.sub())
                    .expect("We just inserted it");
                let sub_hash = Sha256::digest(ec.sub()).into();
                trust_graph.add_edge(
                    sub_hash,
                    leaf_sub_hash,
                    subordinate.payload_unverified().insecure().clone(),
                );

                let _ = Box::pin(entry.complete_trust_async_with_config::<Config>(
                    &mut old_entities,
                    trust_anchors,
                    trust_graph,
                ))
                .await;
                *trust_entities = old_entities;
            }
        }
        for subordinate_statement in &self.subordinate_statement {
            if leaf_ec.sub() != subordinate_statement.payload_unverified().insecure().sub() {
                return Err(TrustChainError::SubjectMismatch(
                    "Subordinate statement sub does not match".to_string(),
                )
                .into());
            }
        }
        Ok(())
    }
    #[instrument(err, skip(self, trust_entities))]
    pub fn complete_trust(
        &mut self,
        trust_entities: &mut HashMap<String, Entity>,
        trust_anchors: &mut Vec<String>,
        trust_graph: &mut DiGraphMap<[u8; 32], EntityStatement>,
    ) -> Result<(), FederationError> {
        self.complete_trust_with_config::<DefaultConfig>(trust_entities, trust_anchors, trust_graph)
    }

    #[instrument(err, skip(self, trust_entities))]
    pub fn complete_trust_with_config<Config: FetchConfig>(
        &mut self,
        trust_entities: &mut HashMap<String, Entity>,
        trust_anchors: &mut Vec<String>,
        trust_graph: &mut DiGraphMap<[u8; 32], EntityStatement>,
    ) -> Result<(), FederationError> {
        // If we have no entity config, we should already have all trust entities. Hence we can do
        // the graph building offline.
        if self.entity_config.is_none() {
            for subordinate_statement in &self.subordinate_statement {
                let iss_hash: [u8; 32] =
                    Sha256::digest(&subordinate_statement.payload_unverified().insecure().iss)
                        .into();
                let sub_hash: [u8; 32] =
                    Sha256::digest(&subordinate_statement.payload_unverified().insecure().sub)
                        .into();
                trust_graph.add_edge(
                    iss_hash,
                    sub_hash,
                    subordinate_statement
                        .payload_unverified()
                        .insecure()
                        .clone(),
                );
                let mut old_entities = trust_entities.clone();
                if let Some(iss) = trust_entities
                    .get_mut(&subordinate_statement.payload_unverified().insecure().iss)
                {
                    iss.complete_trust_with_config::<Config>(
                        &mut old_entities,
                        trust_anchors,
                        trust_graph,
                    )?;
                }
                *trust_entities = old_entities;
            }
            return Ok(());
        }

        let Some(leaf_ec) = self.entity_config.as_ref() else {
            return Err(TrustChainError::InvalidEntityConfig(
                "Leaf entity config not found".to_string(),
            )
            .into());
        };
        if leaf_ec.verify().is_err() {
            //TODO: refresh leaf
            error!("Leaf entity config verification failed");
        }

        let leaf_sub_hash: [u8; 32] = Sha256::digest(leaf_ec.sub()).into();
        trust_graph.add_edge(
            leaf_sub_hash,
            leaf_sub_hash,
            leaf_ec.payload_unverified().insecure().clone(),
        );

        let is_trust_anchor = leaf_ec
            .payload_unverified()
            .insecure()
            .authority_hints
            .is_none();
        println!(
            "{} : {:?}",
            leaf_ec.payload_unverified().insecure().iss,
            leaf_ec.payload_unverified().insecure().authority_hints
        );
        if is_trust_anchor {
            trust_anchors.push(leaf_ec.payload_unverified().insecure().iss.to_string());
        }

        // check if we have all sub statements from the authorities
        for hint in leaf_ec
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or(vec![])
        {
            if let Some(subordinate_statement) = self
                .subordinate_statement
                .iter()
                .find(|stmt| stmt.payload_unverified().insecure().iss() == hint.as_str())
            {
                let iss_hash: [u8; 32] =
                    Sha256::digest(&subordinate_statement.payload_unverified().insecure().iss)
                        .into();
                trust_graph.add_edge(
                    iss_hash,
                    leaf_sub_hash,
                    subordinate_statement
                        .payload_unverified()
                        .insecure()
                        .clone(),
                );
                let mut old_entities = trust_entities.clone();
                if let Some(iss) = trust_entities
                    .get_mut(&subordinate_statement.payload_unverified().insecure().iss)
                {
                    iss.complete_trust_with_config::<Config>(
                        &mut old_entities,
                        trust_anchors,
                        trust_graph,
                    )?;
                }
                *trust_entities = old_entities;
            } else {
                let ec = leaf_ec.fetch_authority_with_config::<Config>(&hint)?;
                let subordinate = ec.fetch_subordinate_with_config::<Config>(&leaf_ec.sub())?;
                self.subordinate_statement.push(subordinate.clone());
                // update self in trust entities
                if let Some(sub_state) =
                    trust_entities.get_mut(&subordinate.payload_unverified().insecure().sub())
                {
                    sub_state.subordinate_statement.push(subordinate.clone());
                }
                //TODO: is there a better way to handle the self referential issue of entity and completing trust?
                let entry = trust_entities.entry(ec.sub()).or_insert(Entity {
                    entity_config: None,
                    subordinate_statement: vec![],
                });

                if matches!(ec, EntityConfig::TrustAnchor(_)) {
                    trust_anchors.push(ec.sub());
                }
                entry.entity_config = Some(ec.clone());
                let mut old_entities = trust_entities.clone();

                let entry = trust_entities
                    .get_mut(&ec.sub())
                    .expect("We just inserted it");
                let sub_hash = Sha256::digest(ec.sub()).into();
                trust_graph.add_edge(
                    sub_hash,
                    leaf_sub_hash,
                    subordinate.payload_unverified().insecure().clone(),
                );

                let _ = entry.complete_trust_with_config::<Config>(
                    &mut old_entities,
                    trust_anchors,
                    trust_graph,
                );
                *trust_entities = old_entities;
            }
        }
        for subordinate_statement in &self.subordinate_statement {
            if leaf_ec.sub() != subordinate_statement.payload_unverified().insecure().sub() {
                return Err(TrustChainError::SubjectMismatch(
                    "Subordinate statement sub does not match".to_string(),
                )
                .into());
            }
        }
        Ok(())
    }
    pub fn verify(&self) -> Result<(), FederationError> {
        if let Some(entity_config) = self.entity_config.as_ref() {
            entity_config.verify()
        } else {
            Err(TrustChainError::InvalidEntityConfig("EntityConfig is missing".to_string()).into())
        }
    }
}

impl<Config: FetchConfig> FederationRelation<Config> {
    pub fn find_shortest_trust_chain(
        &self,
        trust_anchors: Option<&TrustStore>,
    ) -> Result<Vec<EntityStatement>, FederationError> {
        let Some(ec) = self.leaf.entity_config.as_ref() else {
            return Err(FederationError::TrustChain(
                TrustChainError::InvalidEntityConfig("leaf needs EC".to_string()),
            ));
        };
        let start_hash: [u8; 32] = Sha256::digest(ec.sub()).into();
        let reversed_graph = Reversed(&self.trust_graph);

        let mut queue = VecDeque::new();
        queue.push_front(start_hash);
        let mut visited = HashSet::new();
        visited.insert(start_hash);
        let mut parent: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

        while let Some(current) = queue.pop_front() {
            if let Some(trust_anchors) = trust_anchors
                && trust_anchors.is_trusted(current)
            {
                let mut path = vec![current];
                let mut node = current;
                while let Some(parent_hash) = parent.get(&node) {
                    path.push(*parent_hash);
                    node = *parent_hash;
                }
                path.reverse();
                let mut chain = Vec::new();
                if let Some(entity_config_leaf) = self.trust_graph.edge_weight(path[0], path[0]) {
                    chain.push(entity_config_leaf.clone());
                }
                for window in path.windows(2) {
                    let Some(entity_statement) = self.trust_graph.edge_weight(window[1], window[0])
                    else {
                        return Err(FederationError::TrustChain(TrustChainError::BrokenChain(
                            "No entity statement found".to_string(),
                        )));
                    };
                    chain.push(entity_statement.clone());
                }
                if let Some(root_ec) = self.trust_graph.edge_weight(current, current)
                    && root_ec.authority_hints.is_none()
                    && root_ec.iss == root_ec.sub
                {
                    chain.push(root_ec.clone());
                }
                return Ok(chain);
            }
            // if we define no trust anchors we break after finding the first CA
            else if trust_anchors.is_none()
                && let Some(ec) = self.trust_graph.edge_weight(current, current)
                && ec.authority_hints.is_none()
                && ec.iss == ec.sub
            {
                let mut path = vec![current];
                let mut node = current;
                while let Some(parent_hash) = parent.get(&node) {
                    path.push(*parent_hash);
                    node = *parent_hash;
                }
                path.reverse();
                let mut chain = Vec::new();
                if let Some(entity_config_leaf) = self.trust_graph.edge_weight(path[0], path[0]) {
                    chain.push(entity_config_leaf.clone());
                }
                for window in path.windows(2) {
                    let Some(entity_statement) = self.trust_graph.edge_weight(window[1], window[0])
                    else {
                        return Err(FederationError::TrustChain(TrustChainError::BrokenChain(
                            "No entity statement found".to_string(),
                        )));
                    };
                    chain.push(entity_statement.clone());
                }
                chain.push(ec.clone());
                return Ok(chain);
            }
            for neighbor in
                reversed_graph.neighbors_directed(current, petgraph::Direction::Outgoing)
            {
                if visited.insert(neighbor) {
                    parent.insert(neighbor, current);
                    queue.push_back(neighbor);
                }
            }
        }

        Err(FederationError::TrustChain(TrustChainError::BrokenChain(
            "no valid path found".to_string(),
        )))
    }

    pub fn verify(&self) -> Result<(), Vec<FederationError>> {
        self.verify_with_options(VerificationOptions::default())
    }

    pub fn verify_with_options(
        &self,
        options: VerificationOptions,
    ) -> Result<(), Vec<FederationError>> {
        // leaf needs entity config
        let mut errors = vec![];
        let Some(ec) = self.leaf.entity_config.as_ref() else {
            errors.push(TrustChainError::InvalidEntityConfig(
                "EntityConfig is missing".to_string(),
            ));
            return Err(errors.into_iter().map(|a| a.into()).collect::<Vec<_>>());
        };
        if let Err(e) = ec.verify() {
            errors.push(TrustChainError::InvalidEntityConfig(format!(
                "EntityConfigError: {e}"
            )));
        }
        let sub = self.leaf.entity_config.as_ref().unwrap();
        for sub_state in &self.leaf.subordinate_statement {
            let inner = match sub {
                EntityConfig::Leaf(jwt)
                | EntityConfig::Intermediate(jwt)
                | EntityConfig::TrustAnchor(jwt) => jwt,
            };
            let verification_result = if options.lenient_leaf_entity_config {
                inner.verify_signature(&inner.payload_unverified().insecure().jwks())
            } else {
                inner.verify_signature(&sub_state.payload_unverified().insecure().jwks())
            };
            if let Err(e) = verification_result {
                errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                    "[LEAF] EntityConfigError <-> Subordinate: {e}"
                )));
            }
        }
        if sub
            .payload_unverified()
            .insecure()
            .authority_hints()
            .is_none()
            && !matches!(sub, EntityConfig::TrustAnchor(_))
        {
            errors.push(TrustChainError::LeafNeedsAuthorityHints(
                "EntityConfigError: Missing authority hints".to_string(),
            ));
        }
        let authority_hints = sub
            .payload_unverified()
            .insecure()
            .authority_hints()
            .unwrap_or_default();
        if authority_hints.is_empty() {
            errors.push(TrustChainError::AuthorityHintsMustNotBeEmpty(
                "EntityConfigError: Authority hints must not be empty".to_string(),
            ));
        }
        if self.leaf.subordinate_statement.is_empty() {
            errors.push(TrustChainError::BrokenChain(
                "No authority found for leaf".to_string(),
            ))
        }
        // check each trust entry
        for (sub, statement) in &self.trust_entities {
            println!("Verifying trust for: {sub}");
            // if there is an entity config, verify the signature (at least)
            let is_trustanchor;
            if let Some(entity_config) = statement.entity_config.as_ref() {
                is_trustanchor = matches!(entity_config, EntityConfig::TrustAnchor(..));
                if let Err(e) = entity_config.verify() {
                    errors.push(TrustChainError::InvalidEntityConfig(format!(
                        "Error in {sub} -> {e}"
                    )));
                }
            } else {
                is_trustanchor = false;
            }
            // we for sure need a subordinate statement if we are not a trust anchor
            if statement.subordinate_statement.is_empty() && !is_trustanchor {
                errors.push(TrustChainError::BrokenChain(format!(
                    "sub: broken trust chain {sub}"
                )));
            }
            // check all subordinate statements of this entity (check with the issuer)
            for sub_state in &statement.subordinate_statement {
                let iss = sub_state.payload_unverified().insecure().iss();

                let Some(issuer) = self.trust_entities.get(&iss) else {
                    errors.push(TrustChainError::BrokenChain(format!(
                        "{sub}: missing issuer {iss}"
                    )));
                    continue;
                };

                if let Some(ec) = issuer.entity_config.as_ref() {
                    if let Err(e) = ec.verify() {
                        errors.push(TrustChainError::InvalidEntityConfig(format!(
                            "Error in issuer ec [{iss}] -> {e}"
                        )));
                    }
                    if let Err(e) = sub_state.verify_signature(&ec.jwks()) {
                        errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                            "Error in sub_state [{iss}] -> {e}"
                        )));
                    }
                    // the issuer entity config subject must be equal to the subordinate statement issuer
                    if sub_state.payload_unverified().insecure().iss() != ec.sub() {
                        errors.push(TrustChainError::SubjectMismatch(format!(
                            "Issuer mismatch in sub_state [{iss}]"
                        )));
                    }
                } else {
                    // if we don't have an entity config, we need to check, if there are subordinate statements
                    // that have been issued for `iss`. If so, we need to collect all keys into one set, as the different
                    // subordinate statements may have different key material.
                    let sub_ordinate_keys = issuer
                        .subordinate_statement
                        .iter()
                        .flat_map(|sub_st| {
                            sub_st
                                .payload_unverified()
                                .insecure()
                                .jwks()
                                .0
                                .keys()
                                .into_iter()
                                .cloned()
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    let mut jwk_set = JwkSet::new();
                    for key in sub_ordinate_keys {
                        jwk_set.push_key(key);
                    }
                    if jwk_set.keys().is_empty() {
                        errors.push(TrustChainError::BrokenChain(format!(
                            "Error in issuer statement [{iss}] -> missing issuer statement"
                        )));
                    } else if let Err(e) =
                        sub_state.verify_signature(&heidi_jwt::models::JwkSet(jwk_set))
                    {
                        errors.push(TrustChainError::ConfigNotSignedWithSubordinate(format!(
                            "Error in issuer statement [{iss}] -> {e}"
                        )));
                    }
                }
            }
        }

        if errors.is_empty() {
            return Ok(());
        }
        Err(errors.into_iter().map(|a| a.into()).collect::<Vec<_>>())
    }
    pub fn new(leaf: Entity) -> Self {
        Self {
            leaf,
            trust_entities: HashMap::new(),
            trust_anchors: Vec::new(),
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        }
    }
    pub async fn new_from_url_async(url: &str) -> Result<Self, FederationError> {
        let leaf_entity = Entity {
            entity_config: Some(EntityConfig::load_from_url_async::<Config>(url).await?),
            subordinate_statement: vec![],
        };
        let trust_entities = HashMap::from([(url.to_string(), leaf_entity.clone())]);
        Ok(Self {
            leaf: leaf_entity.clone(),
            trust_anchors: Vec::new(),
            trust_entities,
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        })
    }
    pub fn new_from_url(url: &str) -> Result<Self, FederationError> {
        let leaf_entity = Entity {
            entity_config: Some(EntityConfig::load_from_url::<Config>(url)?),
            subordinate_statement: vec![],
        };
        let trust_entities = HashMap::from([(url.to_string(), leaf_entity.clone())]);
        Ok(Self {
            leaf: leaf_entity.clone(),
            trust_anchors: Vec::new(),
            trust_entities,
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        })
    }
    pub fn from_trust_cache(graph: &[String]) -> Result<Self, FederationError> {
        let mut trust_entities = HashMap::new();
        let mut trust_anchors = Vec::new();
        let mut leaf = None;
        for entity in graph {
            let Ok(entity) = entity.parse::<Jwt<EntityStatement>>() else {
                return Err(FederationError::TrustChain(TrustChainError::BrokenChain(
                    "Cannot parse jwt".to_string(),
                )));
            };
            let statement = entity.payload_unverified().insecure().to_owned();
            let is_ec = statement.iss == statement.sub;
            let entry = trust_entities.entry(statement.sub()).or_insert(Entity {
                entity_config: None,
                subordinate_statement: vec![],
            });
            if is_ec {
                if statement.authority_hints.is_none() {
                    println!("Trust Anchor found {}", statement.sub);
                    trust_anchors.push(statement.sub.to_string());
                    entry.entity_config = Some(EntityConfig::TrustAnchor(entity))
                } else {
                    println!("Entity Config found {}", statement.sub);
                    entry.entity_config = Some(EntityConfig::Leaf(entity.clone()));
                    leaf = Some(statement.sub());
                }
            } else {
                println!("Subordinate Statement found {}", statement.sub);
                entry.subordinate_statement.push(entity);
            }
        }
        let Some(leaf) = leaf else {
            return Err(FederationError::TrustChain(
                TrustChainError::InvalidEntityConfig("No leaf entity found".to_string()),
            ));
        };
        let Some(leaf) = trust_entities.get(&leaf) else {
            return Err(FederationError::TrustChain(
                TrustChainError::InvalidEntityConfig("No leaf entity found".to_string()),
            ));
        };
        Ok(Self {
            leaf: leaf.clone(),
            trust_entities,
            trust_anchors: vec![],
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        })
    }
    #[instrument(skip(chain))]
    pub fn from_trust_chain(chain: &[String]) -> Option<Self> {
        let leaf = chain.first()?;
        let Ok(leaf) = leaf.parse::<Jwt<EntityStatement>>() else {
            return None;
        };
        let root = chain.last()?;
        let Ok(root) = root.parse::<Jwt<EntityStatement>>() else {
            return None;
        };
        let mut leaf_entity = Entity {
            entity_config: Some(EntityConfig::Leaf(leaf.clone())),
            subordinate_statement: vec![],
        };
        let mut trust_entities = HashMap::new();
        for (i, jwt) in chain
            .iter()
            .skip(1)
            .take(chain.len().saturating_sub(2))
            .enumerate()
        {
            let Ok(intermediate) = jwt.parse::<Jwt<EntityStatement>>() else {
                return None;
            };
            if i == 0 {
                leaf_entity.subordinate_statement = vec![intermediate.clone()];
            } else {
                trust_entities.insert(
                    intermediate.payload_unverified().insecure().sub(),
                    Entity {
                        entity_config: None,
                        subordinate_statement: vec![intermediate],
                    },
                );
            }
        }
        trust_entities.insert(
            root.payload_unverified().insecure().sub(),
            Entity {
                entity_config: Some(EntityConfig::TrustAnchor(root)),
                subordinate_statement: vec![],
            },
        );

        Some(Self {
            leaf: leaf_entity,
            trust_anchors: vec![],
            trust_entities,
            trust_graph: DiGraphMap::new(),
            phantom: PhantomData,
        })
    }
    #[instrument(skip(self))]
    pub fn build_trust(&mut self) -> Result<(), FederationError> {
        let mut trust_anchors = vec![];
        let mut trust_graph = DiGraphMap::new();
        self.leaf.complete_trust_with_config::<Config>(
            &mut self.trust_entities,
            &mut trust_anchors,
            &mut trust_graph,
        )?;
        self.trust_anchors = trust_anchors;
        self.trust_graph = trust_graph;
        Ok(())
    }
    #[instrument(skip(self))]
    pub async fn build_trust_async(&mut self) -> Result<(), FederationError> {
        let mut trust_anchors = vec![];
        let mut trust_graph = DiGraphMap::new();
        self.leaf
            .complete_trust_async_with_config::<Config>(
                &mut self.trust_entities,
                &mut trust_anchors,
                &mut trust_graph,
            )
            .await?;
        self.trust_anchors = trust_anchors;
        self.trust_graph = trust_graph;
        Ok(())
    }
    #[instrument(skip(self, trust_store))]
    // Resolve metadata from entity config and metadata_policies following the chains
    pub fn resolve_metadata(&self, trust_store: Option<&TrustStore>) -> HashMap<String, Value> {
        let mut base_metadata =
            if let Some(md) = self.leaf.entity_config.as_ref().and_then(|a| a.metadata()) {
                md.clone()
            } else {
                HashMap::new()
            };
        let Ok(mut best_path) = self.find_shortest_trust_chain(trust_store) else {
            return HashMap::new();
        };
        best_path.reverse();
        let mut policy = HashMap::<String, Policy>::new();
        for p in best_path {
            // Skip entity configs
            if p.iss == p.sub {
                continue;
            }
            if let Some(p) = p.metadata_policy() {
                for (k, p) in p {
                    let Ok(p) = Policy::try_from(serde_json::Value::from(p)) else {
                        // if a policy fails to parse, we skip it.
                        continue;
                    };

                    let e = policy.entry(k).or_default();
                    let _ = e.merge_with(&p);
                }
            }
        }
        //ignore errors on applying policies
        for (entity_type, base_data) in &mut base_metadata {
            if let Some(p) = policy.get(entity_type) {
                let _ = p.apply(base_data);
            }
        }
        base_metadata
    }
}
