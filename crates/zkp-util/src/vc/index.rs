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

use rdf_proofs::{
    context::PROOF_VALUE, reorder_vc_triples, ProofWithIndexMap, VerifiableCredential,
    VerifiableCredentialTriples, VerifiablePresentation,
};
use rdf_util::oxrdf::{Dataset, NamedNode, NamedOrBlankNode, Term};

pub fn index_of_vc(_vc: &VerifiableCredential, value: &Term, terms: &Vec<Term>) -> usize {
    terms.iter().position(|t| t == value).unwrap() + 1
}

pub fn index_of_vc_claim(predicate: &str, value: &Term, terms: &[Term]) -> Option<usize> {
    let predicate = Term::NamedNode(NamedNode::new_unchecked(predicate));
    let credential_subject = Term::NamedNode(NamedNode::new_unchecked(
        "https://www.w3.org/2018/credentials#credentialSubject",
    ));
    let subject = terms
        .chunks_exact(3)
        .find(|triple| triple[1] == credential_subject)?[2]
        .clone();

    // BBS messages start with a secret; each RDF triple contributes its object at 3n + 2.
    terms
        .chunks_exact(3)
        .position(|triple| triple[0] == subject && triple[1] == predicate && triple[2] == *value)
        .map(|triple_idx| 3 * triple_idx + 2 + 1)
}

pub fn index_of_vp(vp_dataset: &Dataset, predicate: &NamedNode, vc_idx: usize) -> Option<usize> {
    let vp: VerifiablePresentation = vp_dataset.try_into().unwrap();

    // get proof value
    let proof_value_encoded = vp.get_proof_value().unwrap();

    // drop proof value from VP proof before canonicalization
    // (otherwise it could differ from the prover's canonicalization)
    let vp_without_proof_value = Dataset::from_iter(
        vp_dataset
            .iter()
            .filter(|q| !(q.predicate == PROOF_VALUE && q.graph_name == vp.proof_graph_name)),
    );

    // canonicalize VP
    let c14n_map_for_disclosed = rdf_util::canon::issue(&vp_without_proof_value).unwrap();
    let canonicalized_vp =
        rdf_util::canon::relabel(&vp_without_proof_value, &c14n_map_for_disclosed).unwrap();

    // decompose canonicalized VP into graphs
    let VerifiablePresentation {
        disclosed_vcs: c14n_disclosed_vc_graphs,
        ..
    } = (&canonicalized_vp).try_into().unwrap();

    // convert to Vecs
    let disclosed_vec = c14n_disclosed_vc_graphs
        .into_values()
        .map(|v| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();

    // deserialize proof value into proof and index_map
    let (_, proof_value_bytes) = multibase::decode(proof_value_encoded).unwrap();
    let ProofWithIndexMap { index_map, .. } =
        ciborium::de::from_reader(proof_value_bytes.as_slice()).unwrap();

    // reorder statements according to index map
    let reordered_vc_triples = reorder_vc_triples(&disclosed_vec, &index_map).unwrap();

    let vc = reordered_vc_triples.iter().nth(vc_idx)?;
    let credential_subject_predicate =
        NamedNode::new_unchecked("https://www.w3.org/2018/credentials#credentialSubject");
    let subject = vc.document.iter().find_map(|(_, triple)| {
        let triple = triple.as_ref()?;
        if triple.predicate != credential_subject_predicate {
            return None;
        }
        match &triple.object {
            Term::NamedNode(subject) => Some(NamedOrBlankNode::NamedNode(subject.clone())),
            Term::BlankNode(subject) => Some(NamedOrBlankNode::BlankNode(subject.clone())),
            _ => None,
        }
    });

    // Claim predicates can also occur elsewhere in the credential (for example
    // in nested data). Prefer the credentialSubject claim, but retain the
    // general lookup for device-binding predicates stored outside it.
    subject
        .and_then(|subject| {
            vc.document.iter().find_map(|(k, triple)| {
                triple.as_ref().and_then(|triple| {
                    (triple.subject == subject.clone().into() && &triple.predicate == predicate)
                        .then_some(3 * k + 1 + 1)
                })
            })
        })
        .or_else(|| {
            vc.document.iter().find_map(|(k, triple)| {
                triple
                    .as_ref()
                    .and_then(|triple| (&triple.predicate == predicate).then_some(3 * k + 1 + 1))
            })
        })
}
