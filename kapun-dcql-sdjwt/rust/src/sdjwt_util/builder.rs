/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use kapun_util_rust::{log::log, value::Value};
use sha2::{Digest, Sha256};

#[cfg(feature = "experimental")]
use super::zkp::ZkProof;
use crate::{
    SignatureCreator,
    sdjwt::SdJwtRust,
    sdjwt_util::{
        Disclosure, DisclosureIndex, DisclosureNode, DisclosureTree, Header, base64_hash,
        hash_algs::SdJwtHasher,
    },
};
use kapun_credential_core_rust::{
    claims_pointer::Selector,
    generate_nonce,
    models::{Pointer, PointerPart},
};

// This builder implements the OpenID4VP 1.0 SD-JWT transaction-data hash profile.
// Callers must validate the type-specific schema, select an eligible credential, and
// obtain consent before using this low-level API. Other profiles need their own binding.
fn validate_transaction_data(data: &[String]) -> Result<(), BuilderError> {
    let invalid = |message: &str| BuilderError::InvalidTransactionData(message.into());
    if data.is_empty() {
        return Err(invalid("Transaction data must not be empty"));
    }
    for encoded in data {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| invalid("Transaction data must be unpadded base64url"))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("Transaction data must contain a JSON object"))?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid("Transaction data must be an object"))?;
        if object
            .get("type")
            .and_then(|v| v.as_str())
            .is_none_or(str::is_empty)
        {
            return Err(invalid("Transaction data requires a type"));
        }
        let ids = object
            .get("credential_ids")
            .and_then(|v| v.as_array())
            .ok_or_else(|| invalid("Transaction data requires credential_ids"))?;
        if ids.is_empty() || ids.iter().any(|v| v.as_str().is_none_or(str::is_empty)) {
            return Err(invalid("credential_ids must contain non-empty strings"));
        }
        if let Some(algorithms) = object.get("transaction_data_hashes_alg") {
            let algorithms = algorithms
                .as_array()
                .ok_or_else(|| invalid("Invalid hash algorithm list"))?;
            if algorithms
                .iter()
                .any(|v| v.as_str().is_none_or(str::is_empty))
                || !algorithms.iter().any(|v| v.as_str() == Some("sha-256"))
            {
                return Err(invalid("Requested hash algorithms do not permit sha-256"));
            }
        }
    }
    Ok(())
}

const UNDISCLOSABLE_CLAIMS: [&str; 5] = ["iss", "iat", "exp", "nbf", "vct"];

#[derive(Debug, uniffi::Error, Clone)]
pub enum BuilderError {
    InvalidPath(String),
    InvalidHashAlg,
    Lock,
    Unknown,
    AlreadyBuilt,
    InvalidDisclosure,
    InvalidTransactionData(String),
}

impl Display for BuilderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

#[derive(Debug, Clone)]
pub struct BuilderImpl {
    claims: Value,
    original_jwt: String,
    disclosure_map: HashMap<String, Disclosure>,
    disclosure_tree: DisclosureTree,

    disclosures: Vec<String>,
    nonce: Option<String>,
    aud: Option<String>,
    transaction_data: Option<Vec<String>>,
    #[cfg(feature = "experimental")]
    zk_proofs: Vec<ZkProof>,

    is_w3c: bool,
}

impl BuilderImpl {
    fn resolve_pointer(&self, ptr: Pointer) -> Result<Vec<String>, BuilderError> {
        let mut current = &self.disclosure_tree;
        let ptr_str = format!("{ptr:?}");
        log(
            kapun_util_rust::log::LogPriority::ERROR,
            "SDJWT_BUILDER",
            &format!("Disclosures: {:?}", current),
        );

        let ptr_len = ptr.len();
        let mut it = ptr.into_iter().peekable();
        while let Some(p) = it.next() {
            let index = match p {
                PointerPart::String(s) => DisclosureIndex::String(s),
                PointerPart::Index(i) => DisclosureIndex::Index(i),
                PointerPart::Null(_) => {
                    return Err(BuilderError::InvalidPath("Null pointer part".to_string()));
                }
            };
            let Some(node) = current.get(&index) else {
                return Err(BuilderError::InvalidPath(format!(
                    "No disclosure found for index: {index:?} in path: {ptr_str}"
                )));
            };
            match node {
                DisclosureNode::Node(subtree) => {
                    log(
                        kapun_util_rust::log::LogPriority::ERROR,
                        "SDJWT_BUILDER",
                        &format!("---> {subtree:?} {:?}", it.peek()),
                    );
                    current = subtree;
                }
                DisclosureNode::Leaf(disc) if it.peek().is_none() => {
                    log(
                        kapun_util_rust::log::LogPriority::ERROR,
                        "SDJWT_BUILDER",
                        &format!("---> {disc:?}"),
                    );
                    return Ok(disc.iter().map(|e| e.enc.to_string()).collect());
                }
                _ => {
                    return Err(BuilderError::InvalidPath(format!(
                        "Expected leaf node at end of path: {ptr_str}, found: {node:?}"
                    )));
                }
            }
        }

        // There was something in the path, but we didn't return it yet
        if ptr_len > 0 {
            let disclosures = current
                .values()
                .flat_map(|node| node.get_disclosures())
                .collect::<Vec<_>>();

            if !disclosures.is_empty() {
                return Ok(disclosures.iter().map(|d| d.enc.to_string()).collect());
            }
        }

        Err(BuilderError::InvalidPath(format!(
            "Pointer did not resolve to a disclosure: {ptr_str}"
        )))
    }

    pub fn add_disclosure(&mut self, p: Pointer) -> Result<&mut Self, BuilderError> {
        let disclosure = self.resolve_pointer(p)?;
        for d in disclosure {
            self.disclosures.push(d);
        }
        self.disclosures.sort();
        self.disclosures.dedup();
        Ok(self)
    }
    #[cfg(feature = "experimental")]
    pub fn add_zkp(&mut self, zkp: &ZkProof) -> Result<&mut Self, BuilderError> {
        self.zk_proofs.push(zkp.clone());
        Ok(self)
    }

    pub fn add_all(&mut self) -> Result<&mut Self, BuilderError> {
        let all_disclosures = self.disclosure_map.values().map(|d| d.enc.clone());
        self.disclosures.extend(all_disclosures);
        self.disclosures.sort();
        self.disclosures.dedup();
        Ok(self)
    }

    pub fn remove_disclosure(&mut self, p: Pointer) -> Result<&mut Self, BuilderError> {
        let disclosure = self.resolve_pointer(p)?;
        for disc in disclosure {
            self.disclosures.retain(|d| d != &disc);
        }
        Ok(self)
    }

    pub fn remove_all(&mut self) -> Result<&mut Self, BuilderError> {
        self.disclosures.clear();
        Ok(self)
    }

    pub fn with_nonce(&mut self, nonce: &str) -> Result<&mut Self, BuilderError> {
        self.nonce = Some(nonce.to_string());
        Ok(self)
    }

    pub fn with_audience(&mut self, aud: &str) -> Result<&mut Self, BuilderError> {
        self.aud = Some(aud.to_string());
        Ok(self)
    }

    pub fn with_transaction_data(
        &mut self,
        transaction_data: Vec<String>,
    ) -> Result<&mut Self, BuilderError> {
        validate_transaction_data(&transaction_data)?;
        self.transaction_data = Some(transaction_data);
        Ok(self)
    }

    pub fn build(
        &mut self,
        signer: Option<Arc<dyn SignatureCreator>>,
    ) -> Result<String, BuilderError> {
        if self.transaction_data.is_some()
            && (self
                .claims
                .get("cnf")
                .is_none_or(|cnf| matches!(cnf, Value::Null))
                || signer.is_none())
        {
            return Err(BuilderError::InvalidTransactionData(
                "Transaction data requires cryptographic holder binding".into(),
            ));
        }
        let mut presentation = self.original_jwt.clone();

        if !self.disclosures.is_empty() {
            presentation.push_str(&format!("~{}", self.disclosures.join("~")));
        }

        presentation.push('~');

        if self.claims.get("cnf").is_some() {
            if let Some(signer) = signer {
                let jwt = {
                    let hash_alg = self
                        .claims
                        .get("_sd_alg")
                        .and_then(|s| s.as_str())
                        .unwrap_or("sha-256");

                    let Ok(digest) = hash_alg.parse::<SdJwtHasher>() else {
                        return Err(BuilderError::InvalidHashAlg);
                    };

                    if let Some(params) = self.claims.get("_sd_alg_param") {
                        let param: serde_json::Value = params.into();
                        let mut mut_digest = digest.0.lock().unwrap();
                        mut_digest.update_params(&param);
                    }

                    let header = {
                        let mut header = Header::new(signer.alg().as_str());
                        header.typ = "kb+jwt".to_string();

                        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap())
                    };

                    let body = {
                        let nonce = self.nonce.clone().unwrap_or(generate_nonce(32));

                        let iat = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        let sd_hash = digest.0.lock().unwrap().sd_hash(presentation.as_bytes());

                        let mut claims = serde_json::json!({
                            "nonce": nonce,
                            "iat": iat,
                            "sd_hash": sd_hash,
                        });

                        if let Some(aud) = &self.aud {
                            claims["aud"] = serde_json::json!(aud);
                        }
                        #[cfg(feature = "experimental")]
                        if !self.zk_proofs.is_empty() {
                            claims["zk_proofs"] = serde_json::json!(self.zk_proofs);
                        }

                        if let Some(transaction_data) = &self.transaction_data {
                            let hashes = transaction_data
                                .iter()
                                .map(|td| base64_hash(&mut Sha256::new(), td))
                                .collect::<Vec<_>>();
                            claims["transaction_data_hashes"] = serde_json::json!(hashes);
                            claims["transaction_data_hashes_alg"] = serde_json::json!("sha-256");
                        }

                        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
                    };

                    let signature = {
                        let signature = signer
                            .sign(format!("{header}.{body}").as_bytes().to_vec())
                            .unwrap();
                        BASE64_URL_SAFE_NO_PAD.encode(signature)
                    };

                    format!("{header}.{body}.{signature}")
                };
                presentation.push_str(&jwt);
            }
        }
        Ok(presentation)
    }
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct SdJwtBuilder {
    inner: Arc<Mutex<BuilderImpl>>,
}

//TODO: UBAM figure out how to expose this to kmp
impl SdJwtBuilder {
    #[cfg(feature = "experimental")]
    pub fn add_zkp(&self, zkp: ZkProof) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.zk_proofs.push(zkp);
        Ok(())
    }
}

impl SdJwtBuilder {
    pub fn from_parts(
        claims: Value,
        original_jwt: String,
        disclosure_map: HashMap<String, Disclosure>,
        disclosure_tree: DisclosureTree,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BuilderImpl {
                claims,
                original_jwt,
                disclosure_map,
                disclosure_tree,
                disclosures: vec![],
                nonce: None,
                aud: None,
                #[cfg(feature = "experimental")]
                zk_proofs: vec![],
                transaction_data: None,
                is_w3c: true,
            })),
        }
    }
}

#[uniffi::export]
impl SdJwtBuilder {
    #[uniffi::constructor]
    pub fn from_sdjwt(sdjwt: &SdJwtRust) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BuilderImpl {
                claims: sdjwt.claims.clone(),
                original_jwt: sdjwt.original_jwt.clone(),
                disclosure_map: sdjwt.disclosures_map.clone(),
                disclosure_tree: sdjwt.disclosure_tree.clone(),
                disclosures: vec![],
                nonce: None,
                aud: None,
                transaction_data: None,
                #[cfg(feature = "experimental")]
                zk_proofs: vec![],
                is_w3c: false,
            })),
        }
    }

    pub fn add_disclosure(&self, p: Pointer) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        let Some(first) = p.first() else {
            return Err(BuilderError::InvalidPath("Empty pointer path".to_string()));
        };

        if UNDISCLOSABLE_CLAIMS
            .iter()
            .any(|uc| matches!(first, PointerPart::String(c) if &c == uc))
        {
            return Err(BuilderError::InvalidDisclosure);
        }

        let Ok(resolver) = p.resolve_ptr(this.claims.clone()) else {
            return Err(BuilderError::InvalidPath(
                "Failed to resolve pointer".to_string(),
            ));
        };

        for p in resolver {
            this.add_disclosure(p)?;
        }

        Ok(())
    }

    pub fn add_all(&self) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.add_all()?;

        Ok(())
    }

    pub fn remove_disclosure(&self, p: Pointer) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.remove_disclosure(p)?;

        Ok(())
    }

    pub fn remove_all(&self) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.remove_all()?;

        Ok(())
    }

    pub fn with_nonce(&self, nonce: &str) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.with_nonce(nonce)?;

        Ok(())
    }

    pub fn with_audience(&self, aud: &str) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.with_audience(aud)?;

        Ok(())
    }

    pub fn with_transaction_data(&self, transaction_data: Vec<String>) -> Result<(), BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        this.with_transaction_data(transaction_data)?;

        Ok(())
    }

    pub fn build(&self, signer: Option<Arc<dyn SignatureCreator>>) -> Result<String, BuilderError> {
        let Ok(mut this) = self.inner.lock() else {
            return Err(BuilderError::Lock);
        };

        let result = this.build(signer)?;
        Ok(result)
    }

    pub fn get_disclosure_tree(&self) -> DisclosureTree {
        let this = self.inner.lock().unwrap();
        this.disclosure_tree.clone()
    }

    pub fn is_w3c(&self) -> bool {
        let this = self.inner.lock().unwrap();
        this.is_w3c
    }
}

#[cfg(test)]
mod transaction_data_tests {
    use super::*;
    use crate::SigningError;
    use serde_json::json;

    struct TestSigner;
    impl SignatureCreator for TestSigner {
        fn alg(&self) -> String {
            "ES256".into()
        }
        fn sign(&self, _: Vec<u8>) -> Result<Vec<u8>, SigningError> {
            Ok(vec![1, 2, 3])
        }
    }

    fn builder(bound: bool) -> SdJwtBuilder {
        let claims = if bound {
            json!({"cnf": {"jwk": {}}})
        } else {
            json!({})
        };
        SdJwtBuilder::from_parts(
            Value::from_serialize(&claims).unwrap(),
            "header.claims.signature".into(),
            HashMap::new(),
            HashMap::new(),
        )
    }
    fn data(algorithms: Option<serde_json::Value>) -> String {
        let mut data = json!({"type":"https://example.com/transaction", "credential_ids":["pid"]});
        if let Some(algorithms) = algorithms {
            data["transaction_data_hashes_alg"] = algorithms;
        }
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data).unwrap())
    }

    #[test]
    fn hashes_original_encoded_strings_in_key_binding_jwt() {
        let data = vec![data(None), data(Some(json!(["sha-512", "sha-256"])))];
        let builder = builder(true);
        builder.with_nonce("nonce").unwrap();
        builder.with_audience("audience").unwrap();
        builder.with_transaction_data(data.clone()).unwrap();
        let presentation = builder.build(Some(Arc::new(TestSigner))).unwrap();
        let kb = presentation.rsplit('~').next().unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(kb.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let expected: Vec<_> = data
            .iter()
            .map(|encoded| BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes())))
            .collect();
        assert_eq!(claims["transaction_data_hashes"], json!(expected));
        assert_eq!(claims["transaction_data_hashes_alg"], "sha-256");
        assert!(claims.get("transaction_data").is_none());
    }

    // OpenID4VP 1.0 Final §5.1 example, compact JSON, hashed per §B.3.3.1.
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.1
    #[test]
    fn final_spec_example_has_known_transaction_hash() {
        let encoded =
            "eyJ0eXBlIjoiZXhhbXBsZV90eXBlIiwiY3JlZGVudGlhbF9pZHMiOlsiaWRfY2FyZF9jcmVkZW50aWFsIl19";
        let builder = builder(true);
        builder.with_nonce("nonce").unwrap();
        builder.with_audience("audience").unwrap();
        builder.with_transaction_data(vec![encoded.into()]).unwrap();
        let presentation = builder.build(Some(Arc::new(TestSigner))).unwrap();
        let kb = presentation.rsplit('~').next().unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(kb.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            claims["transaction_data_hashes"],
            json!(["lTp84kYtj5cZfVVmkrjZg-TZnQSfDoGWfNN9YKZo14M"])
        );
    }

    #[test]
    fn rejects_malformed_data_and_unsupported_hash_negotiation() {
        let invalid = vec![
            vec![],
            vec!["!".into()],
            vec![BASE64_URL_SAFE_NO_PAD.encode(b"{}")],
            vec![data(Some(json!([])))],
            vec![data(Some(json!(["sha-512"])))],
            vec![data(Some(json!("sha-256")))],
            vec![data(Some(json!(null)))],
            vec![data(Some(json!(["sha-256", 1])))],
            vec![BASE64_URL_SAFE_NO_PAD.encode(br#"{"type":"example","credential_ids":[]}"#)],
        ];
        for data in invalid {
            assert!(matches!(
                builder(true).with_transaction_data(data),
                Err(BuilderError::InvalidTransactionData(_))
            ));
        }
    }

    #[test]
    fn requires_holder_binding_and_a_signer() {
        let unbound = builder(false);
        unbound.with_transaction_data(vec![data(None)]).unwrap();
        assert!(matches!(
            unbound.build(Some(Arc::new(TestSigner))),
            Err(BuilderError::InvalidTransactionData(_))
        ));
        let bound = builder(true);
        bound.with_transaction_data(vec![data(None)]).unwrap();
        assert!(matches!(
            bound.build(None),
            Err(BuilderError::InvalidTransactionData(_))
        ));
        assert!(builder(false).build(None).is_ok());
    }
}
