/* Copyright 2024 Ubique Innovation AG

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

//! Provides some convenient functions relevant for handling SdJwts
use std::{collections::HashMap, sync::Arc, time::SystemTime};

use anyhow::Context;
use kapun_dcql_sdjwt_rust::sdjwt::decode_sdjwt;

use serde_json::Value;

use crate::{
    ApiError,
    presentation::presentation_exchange::{
        ClaimFormatDesignation, FieldQueryResult, InputDescriptorMappingObject,
    },
    vc::{PresentableCredential, VerifiableCredential},
};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// A simple wrapper around a sdjwt in string form.
pub struct SdJwt {
    pub jwt: String,
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SdJwtProperty {
    key: String,
    value: serde_json::Value,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SdJwtProperty {
    pub fn value(self: Arc<Self>) -> String {
        self.value.to_string()
    }
    pub fn key(self: Arc<Self>) -> String {
        self.key.to_string()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SdJwt {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(jwt: String) -> Self {
        Self { jwt }
    }
    /// Expose the properties of an SDJwt in a more convenient way. We use the resotred sd_jwt to place disclosures within the
    /// Json structure.
    pub fn get_properties(self: &Arc<Self>) -> Result<Vec<Arc<SdJwtProperty>>, ApiError> {
        let (jwt, disclosures, _) = std::panic::catch_unwind(|| sdjwt::sd_jwt_parts(&self.jwt))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let restored_jwt =
            sdjwt::restored_sd_jwt(&jwt, &disclosures).map_err(|err| anyhow::anyhow!(err))?;

        Ok(restored_jwt
            .as_object()
            .context("restored_jwt is not an object!")?
            .iter()
            .filter(|(key, _)| key.as_str() != "cnf")
            .map(|(key, value)| {
                Arc::new(SdJwtProperty {
                    key: key.to_string(),
                    value: value.to_owned(),
                })
            })
            .collect())
    }

    pub fn get_jwt(&self) -> String {
        self.jwt.to_string()
    }

    pub fn get_json(self: &Arc<Self>) -> Option<String> {
        let (jwt, disclosures, _) = sdjwt::sd_jwt_parts(&self.jwt);
        sdjwt::restored_sd_jwt(&jwt, &disclosures)
            .map(|a| a.to_string())
            .ok()
    }
}

/// Get credentials matching the provided [PresentationDefinition]. If valid_at is provided, only return valid
/// credentials.
pub(crate) fn get_matching_credentials(
    credentials: &[VerifiableCredential],
    presentation_definition: &kapun_util_rust::value::Value,
    valid_at: Option<SystemTime>,
) -> Result<Vec<Vec<PresentableCredential>>, ApiError> {
    let credentials = credentials
        .iter()
        .filter(|cred| {
            serde_json::from_str::<Value>(&cred.metadata)
                .ok()
                .and_then(|metadata| {
                    Some(metadata.get("credentialType").as_ref()?.as_str()? == "SdJwt")
                })
                .unwrap_or(false)
        })
        // .map(|vc| (sdjwt::sd_jwt_parts(&vc.payload), vc))
        .map(|vc| {
            // println!(
            //     "{}",
            //     sdjwt::restored_sd_jwt(&jwt, &disclosures)
            //         .map(|v| (v, vc.clone()))
            //         .unwrap()
            //         .0,
            // );

            // sdjwt::restored_sd_jwt(&jwt, &disclosures).map(|v| (v, vc.clone()))
            decode_sdjwt(&vc.payload).map(|v| ((&v.claims).into(), vc.clone()))
        })
        .collect::<Result<Vec<(serde_json::Value, _)>, _>>()
        .map_err(|err| anyhow::anyhow!("{}", err))?;

    let presentables = credentials
        .iter()
        .filter_map(|(credential, vc)| {
            if let Some(valid_at) = valid_at {
                if let Some(expiry) = credential.get("exp").and_then(|exp| exp.as_u64()) {
                    let expiry = std::time::UNIX_EPOCH + std::time::Duration::from_secs(expiry);
                    if valid_at > expiry {
                        return None;
                    }
                }
            }
            let results = presentation_definition
                .get("input_descriptors")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|input_descriptor| {
                    // let credential = crate::value::Value::from(credential.clone());
                    let input_descriptor = input_descriptor.transform().unwrap();
                    crate::presentation::presentation_exchange::evaluate_input_raw(
                        &input_descriptor,
                        credential,
                    )
                    .map(|results| {
                        let obj = InputDescriptorMappingObject {
                            id: input_descriptor.id.clone(),
                            format: ClaimFormatDesignation::VcSdJwt,
                            path: "$".to_string(),
                            path_nested: None,
                        };
                        (
                            results,
                            obj,
                            input_descriptor.group.clone().unwrap_or_default(),
                        )
                    })
                })
                .collect::<Vec<_>>();

            if results.is_empty() {
                return None;
            }
            let mut matches_descriptors = false;
            let submission_requirements = presentation_definition
                .get("submission_requirements")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or(vec![]);
            for requirement in &submission_requirements {
                // let requirement = requirement.transform::<dif_presentation_exchange::presentation_definition::SubmissionRequirement>().unwrap();
                let req_count = requirement.get("count").unwrap().as_i64().unwrap();
                let req_from = requirement.get("from").unwrap().as_str().unwrap();
                let rule = requirement
                    .get("rule")
                    .and_then(|a| a.as_str())
                    .map(|a| a.to_lowercase())
                    .unwrap();
                match rule.as_str() {
                    "pick" => {
                        let howmanytopick = *req_count as usize;
                        let group_to_pick = req_from.to_string();
                        let matching_descriptors = results
                            .iter()
                            .filter(|(_, _, group)| group.contains(&group_to_pick))
                            .count();
                        if howmanytopick > matching_descriptors {
                            continue;
                        }
                        matches_descriptors = true
                    }
                    _ => continue,
                }
            }
            if !matches_descriptors && !submission_requirements.is_empty() {
                return None;
            }

            let data = results;

            let map = data.iter().map(|(_, obj, _)| obj).collect::<Vec<_>>();
            let values = data
                .iter()
                .map(|(results, obj, _)| {
                    (
                        obj,
                        results
                            .iter()
                            .filter_map(|result| match result {
                                FieldQueryResult::Some { value, path } => {
                                    let key = path.clone();
                                    let value = serde_json::to_string(value);

                                    match value {
                                        Err(_) => None,
                                        Ok(value) => Some((key, value)),
                                    }
                                }
                                _ => None,
                            })
                            .collect::<HashMap<String, String>>(),
                    )
                })
                .collect::<Vec<_>>();

            Some(Ok::<_, serde_json::Error>(
                values
                    .into_iter()
                    .filter_map(|(obj, val)| {
                        Some(PresentableCredential {
                            credential: (*vc).clone(),
                            descriptor_map: serde_json::to_string(&map).ok()?,
                            values: val,
                            response_id: obj.id.clone(),
                        })
                    })
                    .collect::<Vec<_>>(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(presentables)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod sd_jwt_test {
    use kapun_util_rust::value::Value;

    use crate::{
        crypto::b64url_decode_bytes, presentation::get_matching_credentials_with_dif_pex,
        vc::VerifiableCredential,
    };

    use super::SdJwtProperty;

    #[test]
    fn get_properties() {
        let jwt = "eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpRd05UTXhNRGd4TXpFM1doY05NalV3TnpBMU1EZ3hNekUzV2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU9GQnE0WU1LZzR3NWZUaWZzeXR3QnVKZi83RTdWaFJQWGlObTUyUzNxMUVUSWdCZFh5REsza1Z4R3hnZUhQaXZMUDN1dU12UzZpREVjN3FNeG12ZHVLT0JrRENCalRBZEJnTlZIUTRFRmdRVWlQaENrTEVyRFhQTFcyL0owV1ZlZ2h5dyttSXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFiZjVUemtjUXpoZldvSW95aTFWTjdkOEk5QnNGS20xTVdsdVJwaDJieUdRSWdLWWtkck5mMnhYUGpWU2JqVy9VLzVTNXZBRUM1WHhjT2FudXNPQnJvQmJVPSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkFnPT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiaUVvYnc4SjlLU1NXVWkwQW4xMVVvTlJvT1dhbzhzNnpoU2o4Uk5xVVplZyJdfSwiX3NkIjpbImFSY3dTQjZoa2dkcTdSWlcxeU02ckJReElScExMUl9laU84MEs1SnpzQlkiLCJmekVvX1g4b2xjMnZhUmlKcnlkWXUxRG9MTkRXVFMxRVJuRTlSRGpfZnBVIiwiSnFoOGhpV2JBLVA0SGRZOEU3VWtaeUluWVVXTVhZcGl5UlFKVGN4dmdidyIsImxGeG5vUDN0OGdzajZuZHF5UEphaDZZRW5kUHNtMjlmZHpvWkdZcy02ek0iLCJwU1VBY01CNG9sSzVYdEtHZkhDNWdTYnc4VjRqRFRqSDhPN3R5YUMtakkwIiwiQ0p5OFhrY3lwWmRGeFhfMXlpY3pvQTB0eXcyM1E4TXVDYzV1akprdjQ5TSIsIlUwVXUxeFZSdzI3a1hlWmppZEVXN2djbDh4VlN1d1FwU2ZXWUkzQzZpZ0UiXSwiYWRkcmVzcyI6eyJfc2QiOlsidTUwOE9WelNSdHM0TmI4aUdEUWZCWXZFQ2VOZEZ2dWdYV0R2NkV3bUVlMCIsIk5QZXA4TS1jYWxNM0cyaDlmZnVNazh2bS13cUxtdnk3d2RIQ0JJVzRqcHciLCI3Wl82czhHZUl3TDQxbkxobGo3U2U4T194UGVxa0ZQN3dmVW9hYWNYWUtRIiwidUpKeGhIWWpTQnpxRFR5SzBsV2d5UXhrYi1naGtrbkhTVWZKbWd4by11NCJdfSwiaXNzdWluZ19jb3VudHJ5IjoiREUiLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJpc3N1aW5nX2F1dGhvcml0eSI6IkRFIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvYyIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJ6ajMweXBiWm5QLUtKMVBjU1NpS0RGOXFScjIyTXFSakRYbTlfalAtZUxJIiwieSI6IlJ2VmdXcTl2SlZEYjV2Y2g3YlB2bkxicGh2elBQMVJFR3ZfVmlWeEdFVG8ifX0sImV4cCI6MTcyMjQ5Nzk0MywiaWF0IjoxNzIxMjg4MzQzLCJhZ2VfZXF1YWxfb3Jfb3ZlciI6eyJfc2QiOlsibWpUYTlfV1NYNUVIbGxmQjc1bXVRMnJGUTJteGtiQ1F3bkxWYUpxblhDWSIsIlBTZXMyUzVCTnBjT0Q3Skt1YTh5eVpBMjFJUWlNVmIydWl1MVRTQ1dWUEEiLCJQZXlPaWNJOFpTbkxvRnJwOURKQl9hOGw2Y3hzRGJLWi16SFZYQWRrYU13IiwiRF9neUZlT0hnVHJPTkJBWnlHSVZ6bkh2dE5OVEdQUjB3RTlJaVJ2c0xUTSIsIkZPOVV5WFpReDFGZDhDNlU0M20zTVRZSE5IVVhXRzNVZlR4X3JlQ3hocjgiLCJyUjBnVGVsd3ZBV190STRIWUhfeV9lcWRIaVpESlA4Rmt1V04tYVZQV3pVIl19fQ._a79xCcABPqdtCnziaofPPAmv2AqrIRD1MVM3TtEr_c_6jwMgXZgH70ovVw6o6Jcb4TtpM0e6WACV0yxfYDaPA~WyJTcV8tdUUtbzdQb0k2a0FSMWFNb3VRIiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJOQmtpYW8wVkFCN0xaRUxCLTRUYjJnIiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyIwQUFBMV9zeFVhZmR3b0JkcHBkU2J3IiwiYmlydGhkYXRlIiwiMTk2NC0wOC0xMiJd~WyJiRENkbVNEbEJUZkEydjhZTTdpYThnIiwiYWdlX2JpcnRoX3llYXIiLDE5NjRd~WyJHTklmX2ZpMFE3MnByS3F2dTRrMFFRIiwiYWdlX2luX3llYXJzIiw1OV0~WyJVUFVpVkxjemxGRHFJY2JSbmRHMkRnIiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyJGb3dYS1pCeVpxNDBUYmVuUUlkMk93IiwibmF0aW9uYWxpdGllcyIsWyJERSJdXQ~WyJaUVpuTkV0NjdGaXdfZVh4cWRHR3dRIiwiMTIiLHRydWVd~WyJwRHFaSHVaZ19xVTJtZkRCWGoyN2tBIiwiMTQiLHRydWVd~WyJOR1NsT1Y1U1NPUE4zQW1BNWNyOWpRIiwiMTYiLHRydWVd~WyJhU2dOV0U2OHdjZTJnd0ZmZEFWOGF3IiwiMTgiLHRydWVd~WyJBckhpRW1JaXhTUlN0WnZMMHhGeE9BIiwiMjEiLHRydWVd~WyJ0OUYzZml2clhIa1pXTEVJV0FFNTJRIiwiNjUiLGZhbHNlXQ~WyJvc1QyRC1aeGFxWVYzVG95UVlaNy13IiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyIwWGQwb2tPdy1qb21IeDhleXBVU0N3IiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyIwMWk2OVdCR0JrUk1JUlhubkJwOVd3IiwiY291bnRyeSIsIkRFIl0~WyJTVHBQSkM1X01XeHFLcDhhYmlmMHZ3IiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJlOWo1WnluUnRkUHpqaGVXYzV0MFR3Iiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkHhup5FIDE3Il0~";

        let (_, disclosures, _) = sdjwt::sd_jwt_parts(jwt);
        let disclosures: Vec<_> = disclosures
            .iter()
            .map(|e| {
                let value = b64url_decode_bytes(e).unwrap();
                let disclosure: serde_json::Value = serde_json::from_slice(&value).unwrap();
                let d = disclosure.as_array().unwrap();

                SdJwtProperty {
                    key: d[1].as_str().unwrap().to_string(),
                    value: d[2].clone(),
                }
            })
            .collect();
        println!("{disclosures:?}");
    }

    #[test]
    fn match_nested_credentials() {
        let credential1: VerifiableCredential = VerifiableCredential { id: 59, identity_id: 13, name: "IKXzNQmofLaT".to_string(), metadata: r#"{"credentialType":"SdJwt"}"#.to_string(), payload: "eyJ4NWMiOlsiTUlJQmFEQ0NBUTZnQXdJQkFnSUlTbTVwN3lhaDdoTXdDZ1lJS29aSXpqMEVBd0l3THpFTE1Ba0dBMVVFQmhNQ1EwZ3hEekFOQmdOVkJBb01CbFZpYVhGMVpURVBNQTBHQTFVRUF3d0dVbTl2ZEVOQk1CNFhEVEkxTURRd01UQTVOVGd3TkZvWERUSTJNRFF3TVRBNU5UZ3dORm93UlRFTU1Bb0dBMVVFQXd3RGVuWjJNUXd3Q2dZRFZRUUtEQU42ZG5ZeEREQUtCZ05WQkFjTUEzcDJkakVNTUFvR0ExVUVDQXdEZW5aMk1Rc3dDUVlEVlFRR0V3SkRTREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRzNENjhhNzVPelU4OU1Uc1hlelpkWEZkbTBlY1FUek1pd2gyMFdKR2ZpbGpXMks3Zmt5Rmdzb0E2TTBOMkdscEFCU0d5eVBsOG04bnA0THlNRnpocWd3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnZkFUdWh3NjlUYW1mWWJoR2hwQ0FSdGV2Z1lrV3hmNTRiSXRQUEVmemdFc0NJUUNjTVhyQm9KYUdwRkdMZFcwRFJmb1NZOUFkbHovNVJCRlBDeUVtOHBsUWx3PT0iXSwia2lkIjoiTUQ4d002UXhNQzh4Q3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRS0RBWlZZbWx4ZFdVeER6QU5CZ05WQkFNTUJsSnZiM1JEUVFJSVNtNXA3eWFoN2hNPSIsInR5cCI6ImRjK3NkLWp3dCIsImFsZyI6IkVTMjU2In0.eyJpc3N1YW5jZV9kYXRlIjoiMjAyNS0wNC0yOVQxNDoyNDo0M1oiLCJ2Y3QiOiJodHRwczovL3NjaGVtYS5leGFtcGxlLmludmFsaWQvc2NoZW1hcy9mb3JtYXQtc3BlY2lmaWMtdGVzdC1sOGRiby8yLjAuMCIsImV4cGlyeV9kYXRlIjoiMjAyNS0wNS0xM1QxNDoyNDo0M1oiLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmludmFsaWQvY3JlZGVudGlhbHMvdGVzdCIsIl9zZCI6WyJDRGg4eU1jZU9pbWRyOFpMcEJuV3EzVTFWVVp3WGlJNEUwSzFvbnllSHlBIiwieGFJbWFDTHZaMnRUS01UOHZBeEJudEl4blZEczFuQ2ptYXp0ZG0xNkZWUSJdLCJpc3N1aW5nX2NvdW50cnkiOiJDSCIsImlzc3VpbmdfYXV0aG9yaXR5IjoiQ0giLCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJkdldSTFlSYXBQX0F4SGNoalRkOXBmVWdIeDBTOHpFdXJ1TzVoUHRoaVdjIiwieSI6IklVT0ZkdkJ5WlF4MFlGZlBVX2ZNdE5HcHVubTd0cXJoLUF4Z1duNFBLbWMifX0sImV4cCI6MTc0NzE0NjI4Mywic2NoZW1hX2lkZW50aWZpZXIiOnsiY3JlZGVudGlhbElkZW50aWZpZXIiOiJmb3JtYXQtc3BlY2lmaWMtdGVzdC1sOGRibyIsInZlcnNpb24iOiIyLjAuMCJ9LCJpYXQiOjE3NDU5MzY2ODMsInJlbmRlciI6eyJ0eXBlIjoiT3ZlcmxheXNDYXB0dXJlQnVuZGxlVjEiLCJvY2EiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmludmFsaWQvb2NhL3Rlc3QuanNvbiJ9LCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsidXJpIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5pbnZhbGlkL3N0YXR1cy1saXN0L3Rva2VuIiwiaWR4Ijo0NjU4Njk1fX19.NpNg1dkrKslQ6DyFUNFtgLvTZogTnQ75xehIHZqFtMTZ_iW7Obdvn6FSZfFV-WWPRQo5WnTBqNZj8yN3aFhagQ~WyJjZk5JdElPMHNDcFptVWZ6cENEZXR3Iiwic29tZV9hdHRyaWJ1dGUiLCJiYiJd~WyJfLXFoRzVOc28weGQ1YmI0YWtZM2NRIiwic3RyZWV0IiwiYWEiXQ~WyI1Y013VF82dVp5a2dmYmt0M0dqbkRnIiwiYWRkcmVzcyIseyJfc2QiOlsiTF9EUmhqSHRraTR5S0Q2UTVRQTEtd3VsR2hqNTlCbnI3VWh3UEVHNjRIQSJdfV0~".to_string() };
        let credential2: VerifiableCredential = VerifiableCredential { id: 40, identity_id: 8, name: "LjVuDyODZsVh".to_string(), metadata: r#"{"credentialType":"Mdoc"}"#.to_string(), payload: "synthetic-test-mdoc".to_string() };
        let credentials: Vec<VerifiableCredential> = vec![credential1, credential2];

        let client_metadata = r#"{
    "id": "b877206f-63b9-4823-ba84-cf3d0da0c06e",
    "input_descriptors": [
      {
        "id": "format-specific-test-l8dbo_sdjwt",
        "name": "All credentials descriptor for SD-JWT format",
        "purpose": "To verify the disclosure of all attributes for the SD-JWT format",
        "format": {
          "vc+sd-jwt": {}
        },
        "group": [
          "group_format-specific-test-l8dbo"
        ],
        "constraints": {
          "fields": [
            {
              "path": [
                "$['address']['street']"
              ],
              "purpose": "purpose for address.street",
              "name": "address.street",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['some_attribute']"
              ],
              "purpose": "purpose for some_attribute",
              "name": "some_attribute",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['vct']"
              ],
              "purpose": "Purpose for vct",
              "name": "VCT sd-jwt",
              "filter": {
                "enum": [
                  "https://schema.example.invalid/schemas/format-specific-test-l8dbo/2.0.0"
                ],
                "type": "string"
              },
              "intent_to_retain": false,
              "optional": false
            }
          ],
          "limit_disclosure": "required"
        }
      },
      {
        "id": "format-specific-test-l8dbo_mdoc",
        "name": "All credentials descriptor for MSO MDOC format",
        "purpose": "To verify the disclosure of all attributes for the MSO MDOC format",
        "format": {
          "mso_mdoc": {
            "alg": [
              "ES256",
              "ES384",
              "ES512",
              "EdDSA"
            ]
          }
        },
        "group": [
          "group_format-specific-test-l8dbo"
        ],
        "constraints": {
          "fields": [
            {
              "path": [
                "$['com.example.test-schema.1']['resident_address_street']"
              ],
              "purpose": "purpose for resident_address_street",
              "name": "resident_address_street",
              "intent_to_retain": false,
              "optional": false
            },
            {
              "path": [
                "$['com.example.test-schema.1']['some_attribute']"
              ],
              "purpose": "purpose for some_attribute",
              "name": "some_attribute",
              "intent_to_retain": false,
              "optional": false
            }
          ],
          "limit_disclosure": "required"
        }
      }
    ],
    "name": "Testing Proof Format Specific",
    "purpose": "For some tests",
    "submission_requirements": [
      {
        "name": "Submission Requirement for format-specific-test-l8dbo",
        "purpose": "Submission requirement for credential scheme format-specific-test-l8dbo",
        "rule": "pick",
        "count": 1,
        "from": "group_format-specific-test-l8dbo"
      }
    ]


}"#;

        let ar: Value = serde_json::from_str(&client_metadata).unwrap();

        // let far_in_the_past = std::time::UNIX_EPOCH;
        // // creds will have certainly expired by then
        // let far_in_the_future = std::time::UNIX_EPOCH + Duration::from_secs(1000 * 365 * 24 * 3600);

        let matching = get_matching_credentials_with_dif_pex(ar, credentials, None).unwrap();

        assert_eq!(matching.len(), 1);
    }
}
