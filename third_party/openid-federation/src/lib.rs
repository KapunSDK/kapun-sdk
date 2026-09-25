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

use std::str::FromStr;

use heidi_jwt::jwt::Jwt;
use serde::{Serialize, de::DeserializeOwned};

use crate::models::{
    errors::{FederationError, InternetError, JwsError},
    trust_chain::FederationRelation,
};

pub mod models;
pub mod policy;
pub type DefaultFederationRelation = FederationRelation;
pub trait FetchConfig {
    const VERIFY_TLS: bool;

    /// Optional user-agent supplied by the embedding application.
    fn user_agent() -> Option<String> {
        None
    }
}

pub struct DefaultConfig;
pub struct NoVerifyConfig;

impl FetchConfig for DefaultConfig {
    const VERIFY_TLS: bool = true;
}
impl FetchConfig for NoVerifyConfig {
    const VERIFY_TLS: bool = false;
}

pub fn fetch_jwt<T, Config>(url: &str) -> Result<Jwt<T>, FederationError>
where
    T: Serialize + DeserializeOwned + std::fmt::Debug,
    Config: FetchConfig,
{
    let mut client = reqwest::blocking::Client::builder();
    client = client.danger_accept_invalid_certs(!Config::VERIFY_TLS);
    if let Some(user_agent) = Config::user_agent() {
        client = client.user_agent(user_agent);
    }
    let client = client.build().unwrap();
    let response = client
        .get(url)
        .send()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?
        .error_for_status()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    let text = response
        .text()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    Jwt::from_str(&text).map_err(|e| FederationError::Jws(JwsError::InvalidFormat(format!("{e}"))))
}
pub async fn fetch_jwt_async<
    T: Serialize + DeserializeOwned + std::fmt::Debug,
    Config: FetchConfig,
>(
    url: &str,
) -> Result<Jwt<T>, FederationError> {
    let mut client = reqwest::Client::builder();
    client = client.danger_accept_invalid_certs(!Config::VERIFY_TLS);
    if let Some(user_agent) = Config::user_agent() {
        client = client.user_agent(user_agent);
    }
    let client = client.build().unwrap();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?
        .error_for_status()
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    let text = response
        .text()
        .await
        .map_err(|e| InternetError::InvalidResponse(format!("{e}")))?;
    Jwt::from_str(&text).map_err(|e| FederationError::Jws(JwsError::InvalidFormat(format!("{e}"))))
}

#[cfg(test)]
mod tests {
    use heidi_jwt::{
        Jwk, JwsHeader, JwsSigner,
        chrono::Duration,
        jwt::{
            Jwt,
            creator::{JwtCreator, Signer},
        },
    };
    use petgraph::dot::{Config, Dot};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tracing::{debug, level_filters::LevelFilter};
    use tracing_subscriber::{FmtSubscriber, fmt::format::FmtSpan};

    use crate::{
        DefaultConfig, DefaultFederationRelation,
        models::{
            self, EntityConfig, EntityStatement,
            trust_chain::{NodeId, TrustAnchor, TrustStore},
        },
    };

    #[test]
    fn test_trust_chain_builder() {
        // let subscriber = FmtSubscriber::builder()
        //     .with_line_number(true)
        //     .with_max_level(LevelFilter::DEBUG)
        //     .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        //     .pretty()
        //     .finish();
        // let _ = tracing::subscriber::set_global_default(subscriber);
        debug!("Test Started");
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let mut trust_chain = DefaultFederationRelation::from_trust_chain(&chain).unwrap();
        let errors = trust_chain.build_trust().err();
        debug!(error = ?errors, "Test Ended");
    }
    #[test]
    fn test_sunet() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let jwt = chain.first().unwrap();
        let ec = jwt.parse::<Jwt<EntityStatement>>().unwrap();
        let config = EntityConfig::TrustAnchor(ec);
        println!("{:?}", config.verify());
    }

    #[test]
    fn refresh() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let chain: models::transformer::Value =
            serde_json::from_str(include_str!("../test_resources/sunet.json")).unwrap();
        let chain: Vec<String> = chain.into_typed_array().unwrap();
        let jwt = chain.first().unwrap();
        let ec = jwt.parse::<Jwt<EntityStatement>>().unwrap();
        let mut config = EntityConfig::TrustAnchor(ec);
        println!("{}", config.payload_unverified().insecure().exp());
        config.refresh::<DefaultConfig>().unwrap();
        println!("{}", config.payload_unverified().insecure().exp());
    }
    #[test]
    fn fetch_from_url() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let issuer = "http://localhost:3000";
        let mut trust_chain = DefaultFederationRelation::new_from_url(issuer).unwrap();
        let res_trust = trust_chain.build_trust();

        let res_verify = trust_chain.verify();
        debug!(error = ?res_trust, "[build_trust]");
        debug!(error = ?res_verify, "[verify_trust]");
        assert!(res_trust.is_ok() && res_verify.is_ok())
    }

    #[test]
    fn fetch_from_url_procivis() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::INFO)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        // let issuer = "https://procivis.staging.findy.fi/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/358cdf66-979f-4ed5-9c64-422f2d7b4992";
        let issuer = "https://procivis.staging.findy.fi/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/df32e904-a260-4cb1-a299-5bb8b42a7ea1/3b0fbc33-68d2-49b9-b339-7b78a797d7ea";
        // let issuer = "https://issuer.waltid.dev.findy.fi/draft13";
        //
        let mut trust_graph = DefaultFederationRelation::new_from_url(issuer).unwrap();
        let res = trust_graph.build_trust();

        tracing::info!(error = ?res, "[build_trust]");
        let res = trust_graph.verify();

        tracing::info!(error = ?res, "[verify_trust]");

        let trust_chain = trust_graph
            .find_shortest_trust_chain(Some(&TrustStore(vec![TrustAnchor::Subject(
                "https://findy.trustregistry.eu".to_string(),
            )])))
            .unwrap();
        for c in trust_chain {
            println!();
            println!("Iss: {:?}", c.iss);
            println!("Sub: {:?}", c.sub());
            println!("Jwks: {:#?}", c.jwks);
            println!();
        }
        let metadata = trust_graph.resolve_metadata(None);
        println!(
            "{}",
            serde_json::to_string(&metadata["openid_credential_issuer"]).unwrap()
        );
    }

    #[test]
    fn create_statements() {
        // let subscriber = FmtSubscriber::builder()
        //     .with_line_number(true)
        //     .with_max_level(LevelFilter::INFO)
        //     .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        //     .pretty()
        //     .finish();
        // let _ = tracing::subscriber::set_global_default(subscriber);
        let root_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let root_jwk = root_key.to_jwk_key_pair();
        println!("create ec");
        let (root_jwt, root_signer) =
            create_ec("root", &Value::Null, &Value::Null, &root_jwk, &Value::Null);

        let root2_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let root2_jwk = root2_key.to_jwk_key_pair();
        println!("create ec");
        let (root2_jwt, root2_signer) = create_ec(
            "root2",
            &Value::Null,
            &Value::Null,
            &root2_jwk,
            &Value::Null,
        );
        println!("create intermediate2");
        let (intermediate2_jwt, intermediate2_key) = create_statement(
            "root",
            "intermediate2",
            &Value::Null,
            &json!({
                "openid_provider": {
                  "id_token_signing_alg_values_supported": {
                    "add": ["RS256", "RS384", "RS512"]
                  },
                },
            }),
            &root_signer,
        );
        let intermediate2_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate2_key)
                .unwrap(),
        );

        // let mitm_signer = heidi_jwt::ES256.signer_from_jwk(&mitm_key).unwrap();
        let (intermediate1_jwt, intermediate1_key) = create_statement(
            "intermediate2",
            "intermediate1",
            &Value::Null,
            &Value::Null,
            &intermediate2_signer,
        );

        let (intermediate_cs, _) = create_cross_signed(
            "root2",
            "intermediate1",
            &Value::Null,
            &Value::Null,
            &root2_signer,
            &intermediate1_key,
        );

        let intermediate1_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate1_key)
                .unwrap(),
        );
        let (leaf_sub, leaf_key) = create_statement(
            "intermediate1",
            "leaf",
            &Value::Null,
            &Value::Null,
            &intermediate1_signer,
        );

        let (leaf_ec, _) = create_ec(
            "leaf",
            &json!({ "openid_provider": {
                "issuer" : "https://test.example.com"
            } }),
            &Value::Null,
            &leaf_key,
            &json!(["intermediate1"]),
        );

        let chain = vec![
            leaf_ec,
            leaf_sub,
            intermediate1_jwt,
            intermediate_cs,
            intermediate2_jwt,
            root_jwt,
            root2_jwt,
        ];

        let mut trust_chain = DefaultFederationRelation::from_trust_cache(&chain).unwrap();

        trust_chain.build_trust().unwrap();
        trust_chain.verify().unwrap();

        let first_anchor: TrustAnchor = TrustAnchor::Subject("root2".to_string());
        let second_anchor: TrustAnchor = TrustAnchor::Subject("root".to_string());

        let trust_store = TrustStore(vec![second_anchor]);
        let paths = trust_chain
            .find_shortest_trust_chain(Some(&trust_store))
            .unwrap();
        println!("Best path found:");
        for s in paths {
            println!("{}", s.sub());
        }

        let resolved_metadata = trust_chain.resolve_metadata(None);
        println!(
            "{}",
            serde_json::to_string_pretty(&resolved_metadata).unwrap()
        );

        println!(
            "{:?}",
            Dot::with_attr_getters(
                &trust_chain.trust_graph,
                &[Config::EdgeNoLabel, Config::NodeNoLabel],
                &|_, id| {
                    if id.0 == id.1 {
                        String::from("color = \"red\", label = \"EntityConfig\"")
                    } else {
                        String::new()
                    }
                },
                &|_, node_id| {
                    {
                        let Some(entity) = trust_chain
                            .trust_entities
                            .iter()
                            .find(|e| NodeId::from(Sha256::digest(e.0)) == node_id.0)
                        else {
                            return String::new();
                        };
                        if let Some(ec) = &entity.1.entity_config {
                            format!("label = \"{}\"", ec.sub())
                        } else {
                            format!(
                                "label = \"{}\"",
                                entity.1.subordinate_statement[0]
                                    .payload_unverified()
                                    .insecure()
                                    .sub()
                            )
                        }
                    }
                }
            )
        );
    }

    #[test]
    fn test_large_federation_relation() {
        // Create Anchor A (node 8)
        let anchor_a_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let anchor_a_jwk = anchor_a_key.to_jwk_key_pair();
        let (anchor_a_jwt, anchor_a_signer) = create_ec(
            "Anchor A",
            &Value::Null,
            &Value::Null,
            &anchor_a_jwk,
            &Value::Null,
        );

        // Create Anchor B (node 9)
        let anchor_b_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let anchor_b_jwk = anchor_b_key.to_jwk_key_pair();
        let (anchor_b_jwt, anchor_b_signer) = create_ec(
            "Anchor B",
            &Value::Null,
            &Value::Null,
            &anchor_b_jwk,
            &Value::Null,
        );

        // Create Anchor C (node 10)
        let anchor_c_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let anchor_c_jwk = anchor_c_key.to_jwk_key_pair();
        let (anchor_c_jwt, anchor_c_signer) = create_ec(
            "Anchor C",
            &Value::Null,
            &Value::Null,
            &anchor_c_jwk,
            &Value::Null,
        );

        // 8 -> 7: Anchor A issues statement about intermediate7
        let (intermediate7_from_a, intermediate7_key) = create_statement(
            "Anchor A",
            "intermediate7",
            &Value::Null,
            &Value::Null,
            &anchor_a_signer,
        );
        let intermediate7_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate7_key)
                .unwrap(),
        );

        // 10 -> 7: Anchor C issues statement about intermediate7
        let (intermediate7_from_c, _) = create_cross_signed(
            "Anchor C",
            "intermediate7",
            &Value::Null,
            &Value::Null,
            &anchor_c_signer,
            &intermediate7_key,
        );

        // 9 -> 6: Anchor B issues statement about intermediate6
        let (intermediate6_from_b, intermediate6_key) = create_statement(
            "Anchor B",
            "intermediate6",
            &Value::Null,
            &Value::Null,
            &anchor_b_signer,
        );
        let intermediate6_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate6_key)
                .unwrap(),
        );

        // 8 -> 6: Anchor A issues statement about intermediate6
        let (intermediate6_from_a, _) = create_cross_signed(
            "Anchor A",
            "intermediate6",
            &Value::Null,
            &Value::Null,
            &anchor_a_signer,
            &intermediate6_key,
        );

        // 10 -> 6: Anchor C issues statement about intermediate6
        let (intermediate6_from_c, _) = create_cross_signed(
            "Anchor C",
            "intermediate6",
            &Value::Null,
            &Value::Null,
            &anchor_c_signer,
            &intermediate6_key,
        );

        // 7 -> 6: intermediate7 issues statement about intermediate6
        let (intermediate6_from_7, _) = create_cross_signed(
            "intermediate7",
            "intermediate6",
            &Value::Null,
            &Value::Null,
            &intermediate7_signer,
            &intermediate6_key,
        );

        // 6 -> 4: intermediate6 issues statement about intermediate4
        let (intermediate4_from_6, intermediate4_key) = create_statement(
            "intermediate6",
            "intermediate4",
            &Value::Null,
            &Value::Null,
            &intermediate6_signer,
        );
        let intermediate4_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate4_key)
                .unwrap(),
        );

        // 7 -> 4: intermediate7 issues statement about intermediate4
        let (intermediate4_from_7, _) = create_cross_signed(
            "intermediate7",
            "intermediate4",
            &Value::Null,
            &Value::Null,
            &intermediate7_signer,
            &intermediate4_key,
        );

        // 10 -> 4: Anchor C issues statement about intermediate4
        let (intermediate4_from_c, _) = create_cross_signed(
            "Anchor C",
            "intermediate4",
            &Value::Null,
            &Value::Null,
            &anchor_c_signer,
            &intermediate4_key,
        );

        // 6 -> 5: intermediate6 issues statement about intermediate5
        let (intermediate5_from_6, intermediate5_key) = create_statement(
            "intermediate6",
            "intermediate5",
            &Value::Null,
            &Value::Null,
            &intermediate6_signer,
        );
        let intermediate5_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate5_key)
                .unwrap(),
        );

        // 4 -> 5: intermediate4 issues statement about intermediate5
        let (intermediate5_from_4, _) = create_cross_signed(
            "intermediate4",
            "intermediate5",
            &Value::Null,
            &Value::Null,
            &intermediate4_signer,
            &intermediate5_key,
        );

        // 10 -> 5: Anchor C issues statement about intermediate5
        let (intermediate5_from_c, _) = create_cross_signed(
            "Anchor C",
            "intermediate5",
            &Value::Null,
            &Value::Null,
            &anchor_c_signer,
            &intermediate5_key,
        );

        // 4 -> 3: intermediate4 issues statement about intermediate3
        let (intermediate3_from_4, intermediate3_key) = create_statement(
            "intermediate4",
            "intermediate3",
            &Value::Null,
            &Value::Null,
            &intermediate4_signer,
        );
        let intermediate3_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate3_key)
                .unwrap(),
        );

        // 5 -> 3: intermediate5 issues statement about intermediate3
        let (intermediate3_from_5, _) = create_cross_signed(
            "intermediate5",
            "intermediate3",
            &Value::Null,
            &Value::Null,
            &intermediate5_signer,
            &intermediate3_key,
        );

        // 3 -> 1: intermediate3 issues statement about intermediate1
        let (intermediate1_from_3, intermediate1_key) = create_statement(
            "intermediate3",
            "intermediate1",
            &Value::Null,
            &Value::Null,
            &intermediate3_signer,
        );
        let intermediate1_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate1_key)
                .unwrap(),
        );

        // 3 -> 2: intermediate3 issues statement about intermediate2
        let (intermediate2_from_3, intermediate2_key) = create_statement(
            "intermediate3",
            "intermediate2",
            &Value::Null,
            &Value::Null,
            &intermediate3_signer,
        );
        let intermediate2_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate2_key)
                .unwrap(),
        );

        // 1 -> 0: intermediate1 issues statement about leaf
        let (leaf_from_1, leaf_key) = create_statement(
            "intermediate1",
            "leaf",
            &Value::Null,
            &Value::Null,
            &intermediate1_signer,
        );

        // 2 -> 0: intermediate2 issues statement about leaf
        let (leaf_from_2, _) = create_cross_signed(
            "intermediate2",
            "leaf",
            &Value::Null,
            &Value::Null,
            &intermediate2_signer,
            &leaf_key,
        );

        // 0 -> 0: leaf entity config
        let (leaf_ec, _) = create_ec(
            "leaf",
            &json!({ "openid_provider": {
                "issuer" : "https://test.example.com"
            } }),
            &Value::Null,
            &leaf_key,
            &json!(["intermediate1", "intermediate2"]),
        );

        let chain = vec![
            leaf_ec,
            leaf_from_1,
            leaf_from_2,
            intermediate1_from_3,
            intermediate2_from_3,
            intermediate3_from_4,
            intermediate3_from_5,
            intermediate4_from_6,
            intermediate4_from_7,
            intermediate4_from_c,
            intermediate5_from_6,
            intermediate5_from_4,
            intermediate5_from_c,
            intermediate6_from_b,
            intermediate6_from_a,
            intermediate6_from_c,
            intermediate6_from_7,
            intermediate7_from_a,
            intermediate7_from_c,
            anchor_a_jwt,
            anchor_b_jwt,
            anchor_c_jwt,
        ];

        let mut trust_chain = DefaultFederationRelation::from_trust_cache(&chain).unwrap();

        trust_chain.build_trust().unwrap();
        trust_chain.verify().unwrap();

        let anchor_a: TrustAnchor = TrustAnchor::Subject("Anchor A".to_string());
        let anchor_b: TrustAnchor = TrustAnchor::Subject("Anchor B".to_string());
        let anchor_c: TrustAnchor = TrustAnchor::Subject("Anchor C".to_string());

        // let trust_store = TrustStore(vec![anchor_a, anchor_b, anchor_c]);
        // let trust_store = TrustStore(vec![anchor_a, anchor_b, anchor_c]);
        let trust_store = TrustStore(vec![anchor_c]);
        let paths = trust_chain
            .find_shortest_trust_chain(Some(&trust_store))
            .unwrap();
        println!("Best path found:");
        for s in paths {
            println!("   {}", s.sub());
        }

        let resolved_metadata = trust_chain.resolve_metadata(None);
        println!(
            "{}",
            serde_json::to_string_pretty(&resolved_metadata).unwrap()
        );

        println!(
            "{:?}",
            Dot::with_attr_getters(
                &trust_chain.trust_graph,
                &[Config::EdgeNoLabel, Config::NodeNoLabel],
                &|_, id| {
                    if id.0 == id.1 {
                        String::from("color = \"red\", label = \"EntityConfig\"")
                    } else {
                        String::new()
                    }
                },
                &|_, node_id| {
                    {
                        let Some(entity) = trust_chain
                            .trust_entities
                            .iter()
                            .find(|e| NodeId::from(Sha256::digest(e.0)) == node_id.0)
                        else {
                            return String::new();
                        };
                        if let Some(ec) = &entity.1.entity_config {
                            format!("label = \"{}\"", ec.sub())
                        } else {
                            format!(
                                "label = \"{}\"",
                                entity.1.subordinate_statement[0]
                                    .payload_unverified()
                                    .insecure()
                                    .sub()
                            )
                        }
                    }
                }
            )
        );
    }

    #[test]
    fn test_example_federation_relation() {
        // Create Anchor A (node 5)
        let anchor_a_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let anchor_a_jwk = anchor_a_key.to_jwk_key_pair();
        let (anchor_a_jwt, anchor_a_signer) = create_ec(
            "Anchor A",
            &Value::Null,
            &Value::Null,
            &anchor_a_jwk,
            &Value::Null,
        );

        // Create Anchor B (node 6)
        let anchor_b_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let anchor_b_jwk = anchor_b_key.to_jwk_key_pair();
        let (anchor_b_jwt, anchor_b_signer) = create_ec(
            "Anchor B",
            &Value::Null,
            &Value::Null,
            &anchor_b_jwk,
            &Value::Null,
        );

        // 5 -> 3: Anchor A issues statement about intermediate3
        let (intermediate3_from_a, intermediate3_key) = create_statement(
            "Anchor A",
            "intermediate3",
            &Value::Null,
            &Value::Null,
            &anchor_a_signer,
        );
        let intermediate3_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate3_key)
                .unwrap(),
        );

        // 6 -> 2: Anchor B issues statement about intermediate2
        let (intermediate2_from_b, intermediate2_key) = create_statement(
            "Anchor B",
            "intermediate2",
            &Value::Null,
            &Value::Null,
            &anchor_b_signer,
        );
        let intermediate2_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate2_key)
                .unwrap(),
        );

        // 6 -> 3: Anchor B issues statement about intermediate3
        let (intermediate3_from_b, _) = create_cross_signed(
            "Anchor B",
            "intermediate3",
            &Value::Null,
            &Value::Null,
            &anchor_b_signer,
            &intermediate3_key,
        );

        // 2 -> 1: intermediate2 issues statement about intermediate1
        let (intermediate1_from_2, intermediate1_key) = create_statement(
            "intermediate2",
            "intermediate1",
            &Value::Null,
            &Value::Null,
            &intermediate2_signer,
        );
        let intermediate1_signer = Box::new(
            heidi_jwt::ES256
                .signer_from_jwk(&intermediate1_key)
                .unwrap(),
        );

        // 3 -> 0: intermediate3 issues statement about leaf A
        let (leaf_a_from_3, leaf_a_key) = create_statement(
            "intermediate3",
            "leaf A",
            &Value::Null,
            &Value::Null,
            &intermediate3_signer,
        );

        // 6 -> 0: Anchor B issues statement about leaf A
        let (leaf_a_from_b, _) = create_cross_signed(
            "Anchor B",
            "leaf A",
            &Value::Null,
            &Value::Null,
            &anchor_b_signer,
            &leaf_a_key,
        );

        // 1 -> 10: intermediate1 issues statement about leaf B
        let (leaf_b_from_1, leaf_b_key) = create_statement(
            "intermediate1",
            "leaf B",
            &Value::Null,
            &Value::Null,
            &intermediate1_signer,
        );

        // 0 -> 0: leaf A entity config
        let (leaf_a_ec, _) = create_ec(
            "leaf A",
            &json!({ "openid_provider": {
                "issuer" : "https://leaf-a.example.com"
            } }),
            &Value::Null,
            &leaf_a_key,
            &json!(["intermediate3", "Anchor B"]),
        );

        // 10 -> 10: leaf B entity config
        let (leaf_b_ec, _) = create_ec(
            "leaf B",
            &json!({ "openid_provider": {
                "issuer" : "https://leaf-b.example.com"
            } }),
            &Value::Null,
            &leaf_b_key,
            &json!(["intermediate1"]),
        );

        let chain = vec![
            leaf_a_ec,
            leaf_b_ec,
            leaf_a_from_3,
            leaf_a_from_b,
            leaf_b_from_1,
            intermediate1_from_2,
            intermediate2_from_b,
            intermediate3_from_a,
            intermediate3_from_b,
            anchor_a_jwt,
            anchor_b_jwt,
        ];

        let mut trust_chain = DefaultFederationRelation::from_trust_cache(&chain).unwrap();

        trust_chain.build_trust().unwrap();
        trust_chain.verify().unwrap();

        let anchor_a: TrustAnchor = TrustAnchor::Subject("Anchor A".to_string());
        let anchor_b: TrustAnchor = TrustAnchor::Subject("Anchor B".to_string());

        let trust_store = TrustStore(vec![anchor_a, anchor_b]);
        let paths = trust_chain
            .find_shortest_trust_chain(Some(&trust_store))
            .unwrap();
        println!("Best path found:");
        for s in paths {
            println!("   {}", s.sub());
        }

        let resolved_metadata = trust_chain.resolve_metadata(None);
        println!(
            "{}",
            serde_json::to_string_pretty(&resolved_metadata).unwrap()
        );

        println!(
            "{:?}",
            Dot::with_attr_getters(
                &trust_chain.trust_graph,
                &[Config::EdgeNoLabel, Config::NodeNoLabel],
                &|_, id| {
                    if id.0 == id.1 {
                        String::from("color = \"red\", label = \"EntityConfig\"")
                    } else {
                        String::new()
                    }
                },
                &|_, node_id| {
                    {
                        let Some(entity) = trust_chain
                            .trust_entities
                            .iter()
                            .find(|e| NodeId::from(Sha256::digest(e.0)) == node_id.0)
                        else {
                            return String::new();
                        };
                        if let Some(ec) = &entity.1.entity_config {
                            format!("label = \"{}\"", ec.sub())
                        } else {
                            format!(
                                "label = \"{}\"",
                                entity.1.subordinate_statement[0]
                                    .payload_unverified()
                                    .insecure()
                                    .sub()
                            )
                        }
                    }
                }
            )
        );
    }

    fn create_ec(
        iss: &str,
        metadata: &Value,
        metadata_policy: &Value,
        root_key: &Jwk,
        authority_hints: &Value,
    ) -> (String, Box<dyn JwsSigner>) {
        let mut public_key = root_key.to_public_key().unwrap();
        public_key.set_key_id(format!("{}", iss));
        let mut root = json!({
            "sub" : iss,
            "jwks" : {
                "keys" : [
                    public_key
                ]
            },
            "metadata" : metadata,
            "metadata_policy" : metadata_policy
        });
        if authority_hints != &Value::Null {
            root["authority_hints"] = authority_hints.clone();
        }
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(heidi_jwt::ES256.name());
        jws_header.set_token_type("entity-statement+jwt");
        jws_header.set_key_id(public_key.key_id().unwrap());
        let new_signer = Box::new(heidi_jwt::ES256.signer_from_jwk(&root_key).unwrap());

        return (
            root.create_jwt(&jws_header, Some(iss), Duration::minutes(2), &new_signer)
                .unwrap(),
            new_signer,
        );
    }
    fn create_statement(
        iss: &str,
        sub: &str,
        metadata: &Value,
        metadata_policy: &Value,
        signer: &dyn Signer,
    ) -> (String, Jwk) {
        let root_key = heidi_jwt::ES256.generate_key_pair().unwrap();
        let mut public_key = root_key.to_jwk_public_key();
        public_key.set_key_id(format!("{}", sub));
        let root = json!({
            "sub" : sub,
            "jwks" : {
                "keys" : [
                    public_key
                ]
            },
            "metadata" : metadata,
            "metadata_policy" : metadata_policy
        });
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(heidi_jwt::ES256.name());
        jws_header.set_token_type("entity-statement+jwt");
        jws_header.set_key_id(iss);

        return (
            root.create_jwt(&jws_header, Some(iss), Duration::minutes(2), signer)
                .unwrap(),
            root_key.to_jwk_key_pair(),
        );
    }
    fn create_cross_signed(
        iss: &str,
        sub: &str,
        metadata: &Value,
        metadata_policy: &Value,
        signer: &dyn Signer,
        key: &Jwk,
    ) -> (String, Jwk) {
        let mut public_key = key.to_public_key().unwrap();
        public_key.set_key_id(format!("{}", sub));
        let root = json!({
            "sub" : sub,
            "jwks" : {
                "keys" : [
                    public_key
                ]
            },
            "metadata" : metadata,
            "metadata_policy" : metadata_policy
        });
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(heidi_jwt::ES256.name());
        jws_header.set_token_type("entity-statement+jwt");
        jws_header.set_key_id(iss);

        return (
            root.create_jwt(&jws_header, Some(iss), Duration::minutes(2), signer)
                .unwrap(),
            key.clone(),
        );
    }
}
