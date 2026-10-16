use std::collections::HashMap;

use kapun_util_rust::value::Value;
use openid_federation::models::trust_chain::{FederationRelation, TrustAnchor, TrustStore};
use openid_federation::FetchConfig;
use serde::{Deserialize, Serialize};

use crate::network::{SdkDefaultConfig, SdkNoVerifyConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct FederationResult {
    is_valid: bool,
    metadata: HashMap<String, Value>,
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum MetadataFetchError {
    FetchFailed(String),
    BuildTrustError(String),
}

impl std::fmt::Display for MetadataFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataFetchError::FetchFailed(inner) => {
                write!(f, "OpenID Federation failed to fetch metadata: {inner}")
            }
            MetadataFetchError::BuildTrustError(inner) => {
                write!(f, "OpenID Federation failed to build trust: {inner}")
            }
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
/// Use OpenID Federation to fetch a certain entity type.
pub async fn fetch_metadata_from_issuer_url(
    url: &str,
    trust_store: Option<Vec<String>>,
) -> Result<FederationResult, MetadataFetchError> {
    if kapun_util_rust::network::untrusted_tls_allowed() {
        fetch_metadata_from_issuer_url_with_config::<SdkNoVerifyConfig>(url, trust_store).await
    } else {
        fetch_metadata_from_issuer_url_with_config::<SdkDefaultConfig>(url, trust_store).await
    }
}

async fn fetch_metadata_from_issuer_url_with_config<Config: FetchConfig>(
    url: &str,
    trust_store: Option<Vec<String>>,
) -> Result<FederationResult, MetadataFetchError> {
    let mut res_oidf = match FederationRelation::<Config>::new_from_url_async(url).await {
        Ok(res_oidf) => res_oidf,
        Err(e) => {
            return Err(MetadataFetchError::FetchFailed(format!(
                "Federation failed with: {e}"
            )))
        }
    };
    res_oidf.build_trust_async().await.map_err(|e| {
        MetadataFetchError::BuildTrustError(format!("Failed to construct trust: {e}"))
    })?;
    let is_valid = res_oidf.verify().is_ok();
    let trust_store = trust_store.map(|anchors| {
        TrustStore(
            anchors
                .into_iter()
                .map(TrustAnchor::Subject)
                .collect::<Vec<_>>(),
        )
    });
    let metadata = res_oidf.resolve_metadata(trust_store.as_ref());
    let mut new_metadata = HashMap::new();
    for (key, data) in metadata {
        let intermediate: serde_json::Value = data.into();
        new_metadata.insert(key, intermediate.into());
    }
    Ok(FederationResult {
        is_valid,
        metadata: new_metadata,
    })
}
