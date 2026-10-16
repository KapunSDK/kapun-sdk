use heidi_jwt::jwt::GeneralizedBody;
use oidcf::models::transformer;
use oidcf::models::trust_chain::FederationRelation;
use oidcf::models::{EntityConfig, EntityStatement};
use openid_federation as oidcf;
use std::{
    fmt::Display,
    sync::atomic::{AtomicBool, Ordering},
};

static ALLOW_UNTRUSTED_TLS: AtomicBool = AtomicBool::new(false);

#[uniffi::export]
/// Set the user-agent in this native library's private kapun-util copy.
pub fn set_user_agent(user_agent: Option<String>) {
    kapun_util_rust::network::set_user_agent(user_agent);
}

#[doc(hidden)]
#[inline(never)]
pub fn uniffi_link_anchor() -> u8 {
    5
}

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FederationError {
    JwtParsingFailed(anyhow::Error),
    FetchingFailed(anyhow::Error),
    ValidationFailed(anyhow::Error),
}

impl Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationError::JwtParsingFailed(e) => {
                f.write_str(&format!("FederationError::JwtParsingFailed: {e}"))
            }
            FederationError::FetchingFailed(e) => {
                f.write_str(&format!("FederationError::FetchingFailed: {e}"))
            }
            FederationError::ValidationFailed(e) => {
                f.write_str(&format!("FederationError::ValidationFailed: {e}"))
            }
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OidcfTrustChainInfo {
    trust_anchor_keys: Vec<TrustAnchor>, // JWKs
    subordinate_statements: Vec<String>, // JWTs
    leaf: OidcfLeafInfo,
}
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustAnchor {
    key: String,
    sub: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OidcfLeafInfo {
    domain: String,
    // extracted metadata
    display_name: String,
    logo_uri: Option<String>,
    credential_configurations_supported: Option<Vec<String>>,
}

#[uniffi::export]
/// Allow or reject invalid TLS certificates and hostnames for trust-network requests.
pub fn set_untrusted_tls(allow: bool) {
    ALLOW_UNTRUSTED_TLS.store(allow, Ordering::Relaxed);
    kapun_util_rust::network::set_untrusted_tls(allow);
}

#[uniffi::export]
pub fn oidcf_trust_chain_from_url(
    url: &str,
    lenient_leaf_entity_config: bool,
) -> Result<OidcfTrustChainInfo, FederationError> {
    if ALLOW_UNTRUSTED_TLS.load(Ordering::Relaxed) {
        oidcf_trust_chain_from_url_with_config::<kapun_util_rust::network::SdkNoVerifyConfig>(
            url,
            lenient_leaf_entity_config,
        )
    } else {
        oidcf_trust_chain_from_url_with_config::<kapun_util_rust::network::SdkDefaultConfig>(
            url,
            lenient_leaf_entity_config,
        )
    }
}

fn oidcf_trust_chain_from_url_with_config<Config: oidcf::FetchConfig>(
    url: &str,
    lenient_leaf_entity_config: bool,
) -> Result<OidcfTrustChainInfo, FederationError> {
    let wrap_fetch_error = |e: oidcf::models::errors::FederationError| {
        FederationError::FetchingFailed(anyhow::anyhow!(e))
    };

    let mut trust_chain =
        FederationRelation::<Config>::new_from_url(url).map_err(wrap_fetch_error)?;

    validate_oidf_trust_chain(&mut trust_chain, lenient_leaf_entity_config)?;
    to_oidf_trust_chain_info(trust_chain, lenient_leaf_entity_config)
}

#[uniffi::export]
pub fn oidcf_trust_chain_from_presentation_request(
    presentation_request_jwt: String,
    lenient_leaf_entity_config: bool,
) -> Result<OidcfTrustChainInfo, FederationError> {
    if ALLOW_UNTRUSTED_TLS.load(Ordering::Relaxed) {
        oidcf_trust_chain_from_presentation_request_with_config::<
            kapun_util_rust::network::SdkNoVerifyConfig,
        >(presentation_request_jwt, lenient_leaf_entity_config)
    } else {
        oidcf_trust_chain_from_presentation_request_with_config::<
            kapun_util_rust::network::SdkDefaultConfig,
        >(presentation_request_jwt, lenient_leaf_entity_config)
    }
}

fn oidcf_trust_chain_from_presentation_request_with_config<Config: oidcf::FetchConfig>(
    presentation_request_jwt: String,
    lenient_leaf_entity_config: bool,
) -> Result<OidcfTrustChainInfo, FederationError> {
    let wrap_parse_error = |e: heidi_jwt::models::errors::JwtError| {
        FederationError::JwtParsingFailed(anyhow::anyhow!(e))
    };
    let wrap_fetch_error = |e: oidcf::models::errors::FederationError| {
        FederationError::FetchingFailed(anyhow::anyhow!(e))
    };
    let wrap_validation_error = |e: heidi_jwt::models::errors::JwtError| {
        FederationError::ValidationFailed(anyhow::anyhow!(e))
    };

    let jwt = presentation_request_jwt
        .parse::<heidi_jwt::jwt::Jwt<serde_json::Value>>()
        .map_err(wrap_parse_error)?;

    // OpenID4VP 1.0 §5: the wallet MUST ignore `iss`; the client id names the verifier.
    let entity_id = federation_entity_id(jwt.payload_unverified().insecure())?;
    let oidf_trust_chain = jwt
        .payload_unverified()
        .insecure()
        .get("trust_chain")
        .and_then(as_vec_string);

    let mut trust_chain = if let Some(oidf_trust_chain) = oidf_trust_chain {
        FederationRelation::<Config>::from_trust_cache(&oidf_trust_chain).or(Err(
            FederationError::ValidationFailed(anyhow::anyhow!("invalid trust_chain")),
        ))?
    } else {
        FederationRelation::<Config>::new_from_url(&entity_id).map_err(wrap_fetch_error)?
    };
    bind_leaf(&mut trust_chain, &entity_id)?;

    validate_oidf_trust_chain(&mut trust_chain, lenient_leaf_entity_config)?;

    let leaf = trust_chain
        .leaf
        .entity_config
        .as_ref()
        .ok_or(FederationError::ValidationFailed(anyhow::anyhow!(
            "invalid trust chain, no leaf found"
        )))?;
    jwt.verify_signature(&leaf.jwks())
        .map_err(wrap_validation_error)?;

    to_oidf_trust_chain_info(trust_chain, lenient_leaf_entity_config)
}

/// OpenID4VP 1.0 §5.9.3: the client id of a verifier using OpenID Federation is
/// `openid_federation:<entity id>`.
const OPENID_FEDERATION_CLIENT_ID_PREFIX: &str = "openid_federation:";

/// Drafts before OpenID4VP 1.0 sent the bare entity id as `client_id`, with one of these as
/// `client_id_scheme`.
const OPENID_FEDERATION_CLIENT_ID_SCHEMES: [&str; 2] = ["entity_id", "openid_federation"];

/// The entity identifier of the verifier a request's `client_id` names, if it names one through
/// OpenID Federation. Requests with any other client id (`x509_san_dns:`,
/// `decentralized_identifier:`, …) are left to the other trust frameworks, whatever their `iss`.
fn federation_entity_id(request: &serde_json::Value) -> Result<String, FederationError> {
    let not_federation = || {
        FederationError::FetchingFailed(anyhow::anyhow!(
            "client_id does not name an OpenID Federation entity"
        ))
    };
    let client_id = request
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(not_federation)?;
    let entity_id = match client_id.strip_prefix(OPENID_FEDERATION_CLIENT_ID_PREFIX) {
        Some(entity_id) => entity_id,
        None => {
            let scheme = request.get("client_id_scheme").and_then(|v| v.as_str());
            if !scheme.is_some_and(|s| OPENID_FEDERATION_CLIENT_ID_SCHEMES.contains(&s)) {
                return Err(not_federation());
            }
            client_id
        }
    };
    let url = reqwest::Url::parse(entity_id)
        .map_err(|e| FederationError::FetchingFailed(anyhow::anyhow!(e)))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(FederationError::FetchingFailed(anyhow::anyhow!(
            "OIDC Federation entity identifier is not an HTTP(S) URL"
        )));
    }
    // as given: a parsed URL is normalized (e.g. a trailing slash added) and would no longer
    // equal the entity's `sub`
    Ok(entity_id.to_string())
}

/// Makes the entity the client id names the chain's leaf, so that the chain validated and the
/// key the request is verified with are that entity's. Neither a fetched entity configuration nor
/// a `trust_chain` passed by value is otherwise tied to it: the latter could carry any member of
/// a trusted federation, whose key would then vouch for someone else's client id.
fn bind_leaf<Config: oidcf::FetchConfig>(
    trust_chain: &mut FederationRelation<Config>,
    entity_id: &str,
) -> Result<(), FederationError> {
    let leaf = trust_chain
        .trust_entities
        .get(entity_id)
        .filter(|e| {
            e.entity_config
                .as_ref()
                .is_some_and(|config| config.sub() == entity_id)
        })
        .ok_or_else(|| {
            FederationError::ValidationFailed(anyhow::anyhow!(
                "trust chain has no entity configuration for {entity_id}"
            ))
        })?;
    trust_chain.leaf = leaf.clone();
    Ok(())
}

fn validate_oidf_trust_chain<Config: oidcf::FetchConfig>(
    trust_chain: &mut FederationRelation<Config>,
    lenient_leaf_entity_config: bool,
) -> Result<(), FederationError> {
    let wrap_validation_error = |e: oidcf::models::errors::FederationError| {
        FederationError::ValidationFailed(anyhow::anyhow!(e))
    };

    trust_chain.build_trust().map_err(wrap_validation_error)?;
    trust_chain
        .verify_with_options(oidcf::models::trust_chain::VerificationOptions {
            lenient_leaf_entity_config,
        })
        .map_err(|e| wrap_validation_error(e.first().unwrap().clone()))?;
    Ok(())
}

fn to_oidf_trust_chain_info<Config: oidcf::FetchConfig>(
    mut trust_chain: FederationRelation<Config>,
    lenient_leaf_entity_config: bool,
) -> Result<OidcfTrustChainInfo, FederationError> {
    let wrap_validation_error = |e: oidcf::models::errors::FederationError| {
        FederationError::ValidationFailed(anyhow::anyhow!(e))
    };

    trust_chain.build_trust().map_err(wrap_validation_error)?;
    trust_chain
        .verify_with_options(oidcf::models::trust_chain::VerificationOptions {
            lenient_leaf_entity_config,
        })
        .map_err(|e| wrap_validation_error(e.first().unwrap().clone()))?;

    // Prefer metadata resolved through the federation chain, which includes
    // metadata policies, while retaining the leaf metadata as a fallback for
    // chains that do not expose a resolvable path.
    let resolved_metadata = trust_chain.resolve_metadata(None);

    let trust_anchor_keys: Vec<_> = trust_chain
        .trust_entities
        .values()
        .flat_map(|e| e.entity_config.as_ref())
        .filter(|e| matches!(e, EntityConfig::TrustAnchor(_)))
        .flat_map(|ta| {
            let jwks = ta.jwks();
            let keys = jwks
                .0
                .keys()
                .into_iter()
                .map(|jwk| TrustAnchor {
                    key: serde_json::to_string(&jwk.to_public_key().unwrap()).unwrap(),
                    sub: ta.sub(),
                })
                .collect::<Vec<_>>();
            keys.into_iter()
        })
        .collect();
    let subordinate_statements: Vec<_> = trust_chain
        .leaf
        .subordinate_statement
        .iter()
        .map(|jwt| jwt.jwt_at(0))
        .collect();

    let leaf = if let Some(EntityConfig::Leaf(leaf)) = trust_chain.leaf.entity_config {
        let pld = leaf.payload_unverified();
        to_leaf_info(pld.insecure(), &resolved_metadata)
    } else {
        return Err(FederationError::ValidationFailed(anyhow::anyhow!(
            "no leaf"
        )));
    };

    Ok(OidcfTrustChainInfo {
        trust_anchor_keys,
        subordinate_statements,
        leaf,
    })
}

fn as_vec_string(v: &serde_json::Value) -> Option<Vec<String>> {
    v.as_array().map(|a| {
        a.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::{bind_leaf, federation_entity_id};
    use base64::Engine;
    use openid_federation::models::trust_chain::FederationRelation;
    use serde_json::json;

    #[test]
    fn takes_entity_id_from_prefixed_client_id() {
        let request = json!({ "client_id": "openid_federation:https://verifier.example.com/test" });
        assert_eq!(
            federation_entity_id(&request).unwrap(),
            "https://verifier.example.com/test"
        );
    }

    #[test]
    fn keeps_entity_id_as_given() {
        let request = json!({ "client_id": "openid_federation:https://verifier.example.com" });
        assert_eq!(
            federation_entity_id(&request).unwrap(),
            "https://verifier.example.com"
        );
    }

    #[test]
    fn takes_bare_client_id_with_pre_final_client_id_scheme() {
        for scheme in ["entity_id", "openid_federation"] {
            let request = json!({
                "client_id": "https://verifier.example.com",
                "client_id_scheme": scheme,
            });
            assert_eq!(
                federation_entity_id(&request).unwrap(),
                "https://verifier.example.com"
            );
        }
    }

    #[test]
    fn ignores_iss() {
        let request = json!({
            "client_id": "x509_san_dns:verifier.example.com",
            "iss": "https://other.example.com",
        });
        assert!(federation_entity_id(&request).is_err());
        let request = json!({
            "client_id": "openid_federation:https://verifier.example.com",
            "iss": "https://other.example.com",
        });
        assert_eq!(
            federation_entity_id(&request).unwrap(),
            "https://verifier.example.com"
        );
    }

    #[test]
    fn rejects_other_client_ids() {
        for client_id in [
            "decentralized_identifier:did:webvh:example.com:verifier",
            "x509_san_dns:verifier.example.com",
            "https://verifier.example.com",
            "openid_federation:did:web:verifier.example.com",
        ] {
            assert!(federation_entity_id(&json!({ "client_id": client_id })).is_err());
        }
        assert!(federation_entity_id(&json!({})).is_err());
    }

    /// An entity statement as found in a `trust_chain`; its signature is not checked here.
    fn statement(iss: &str, sub: &str, authority_hints: Option<&str>) -> String {
        let b64 = |v: serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        let mut claims = json!({
            "iss": iss, "sub": sub, "iat": 0, "exp": 4_102_444_800i64,
            "jwks": { "keys": [] },
        });
        if let Some(hint) = authority_hints {
            claims["authority_hints"] = json!([hint]);
        }
        format!(
            "{}.{}.{}",
            b64(json!({ "alg": "ES256", "typ": "entity-statement+jwt" })),
            b64(claims),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]),
        )
    }

    const ANCHOR: &str = "https://anchor.example.com";

    fn chain_for(leaf: &str) -> FederationRelation {
        FederationRelation::from_trust_cache(&[
            statement(leaf, leaf, Some(ANCHOR)),
            statement(ANCHOR, leaf, None),
            statement(ANCHOR, ANCHOR, None),
        ])
        .unwrap()
    }

    #[test]
    fn binds_leaf_named_by_client_id() {
        let mut chain = chain_for("https://verifier.example.com");
        bind_leaf(&mut chain, "https://verifier.example.com").unwrap();
        assert_eq!(
            chain.leaf.entity_config.unwrap().sub(),
            "https://verifier.example.com"
        );
    }

    #[test]
    fn rejects_trust_chain_of_another_entity() {
        let mut chain = chain_for("https://attacker.example.com");
        assert!(bind_leaf(&mut chain, "https://verifier.example.com").is_err());
    }
}

fn to_leaf_info(
    leaf: &EntityStatement,
    resolved_metadata: &std::collections::HashMap<String, transformer::Value>,
) -> OidcfLeafInfo {
    let metadata = if resolved_metadata.is_empty() {
        leaf.metadata.as_ref()
    } else {
        Some(resolved_metadata)
    };

    let cred_issuer = metadata.and_then(|v| v.get("openid_credential_issuer"));
    let credential_configurations_supported = cred_issuer
        .and_then(|v| v.get("credential_configurations_supported"))
        .and_then(|v| v.as_object())
        .map(|v| v.keys().cloned().collect::<Vec<_>>());

    // Many different places to get display name and logo from:
    // We just try and pick the first that we find ; no particular order of precedence is defined

    // Attempt to information from credential issuer display metadata
    // - openid_credential_issuer.display[0].name
    // - openid_credential_issuer.display[0].logo.uri
    let cred_issuer_display = cred_issuer
        .and_then(|v| v.get("display"))
        .and_then(|v| v.as_array())
        .and_then(|v| v.first()); // TODO: select based on language?
    let mut display_name = cred_issuer_display
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut logo_uri = cred_issuer_display
        .and_then(|v| v.get("logo"))
        .and_then(|v| v.get("uri"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Alternatively use credential verifier metadata
    //  - OpenID Federation Wallet Architectures 1.0 draft 03
    //  -> openid_credential_verifier metadata as defined in OpenID4VP
    //  -> OpenID4VP "Verifier Metadata"
    //  -> RFC 7591
    //
    // - openid_credential_verifier.client_name
    // - openid_credential_verifier.logo_uri
    let cred_verifier = metadata.and_then(|v| v.get("openid_credential_verifier"));

    display_name = display_name.or_else(|| {
        cred_verifier
            .and_then(|v| v.get("client_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    logo_uri = logo_uri.or_else(|| {
        cred_verifier
            .and_then(|v| v.get("logo_uri"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    // Alternatively use metadata defined by openid-federation.
    // According to OpenID Federation Wallet Architectures 1.0 draft 03,
    // these can exist on any of the Entity Types (openid_credential_issuer, openid_credential_verifier, federation_entity, ...)
    //  - *.display_name
    //  - *.organization_name
    //  - *.logo_uri
    let federation_entity = metadata.and_then(|v| v.get("federation_entity"));

    let oidf_display_name = |obj: &Option<&transformer::Value>| {
        obj.and_then(|v| v.get("display_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                obj.and_then(|v| v.get("organization_name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
    };
    let oidf_logo_uri = |obj: &Option<&transformer::Value>| {
        obj.and_then(|v| v.get("logo_uri"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    display_name = oidf_display_name(&federation_entity)
        .or(display_name)
        .or_else(|| oidf_display_name(&cred_issuer))
        .or_else(|| oidf_display_name(&cred_verifier));
    logo_uri = oidf_logo_uri(&federation_entity)
        .or(logo_uri)
        .or_else(|| oidf_logo_uri(&cred_issuer))
        .or_else(|| oidf_logo_uri(&cred_verifier));

    let domain = federation_entity
        .and_then(|v| v.get("homepage_uri"))
        .and_then(|v| v.as_str())
        .filter(|uri| !uri.is_empty())
        .map(|uri| uri.to_string())
        .unwrap_or_else(|| leaf.sub());
    let display_name = display_name.unwrap_or_else(|| domain.clone());

    OidcfLeafInfo {
        domain,
        display_name,
        logo_uri,
        credential_configurations_supported,
    }
}

#[cfg(target_arch = "arm")]
#[used]
static _KEEP_EH_FRAME_STUBS: [unsafe extern "C" fn(); 2] = [
    kapun_util_rust::__register_frame,
    kapun_util_rust::__deregister_frame,
];

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
