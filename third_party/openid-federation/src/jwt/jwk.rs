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


// use crate::models::errors::{FederationError, X509Error};

// pub fn jwk_from_x509(cert: &str) -> Result<Box<dyn JwsVerifier>, FederationError> {
//     let certificate = if cert.contains("BEGIN") {
//         x509_cert::Certificate::from_pem(cert)
//             .map_err(|_| X509Error::ParseError("Invalid certificate".to_string()))?
//     } else {
//         let decoded_value = BASE64_STANDARD
//             .decode(cert)
//             .map_err(|_| X509Error::ParseError("Invalid certificate".to_string()))?;
//         x509_cert::Certificate::from_der(&decoded_value)
//             .map_err(|_| X509Error::ParseError("Invalid certificate".to_string()))?
//     };
//     let subject_public_key_info = certificate.tbs_certificate.subject_public_key_info;
//     match subject_public_key_info.algorithm.oid {
//         oid if oid == RSA_ENCRYPTION => {
//             let rsa_public_key = subject_public_key_info.subject_public_key.clone();
//             let jwk = Jwk::from_rsa_public_key(&rsa_public_key);
//             Box::new(jwk)
//         }
//         oid if oid == ID_EC_PUBLIC_KEY => {
//             let ec_public_key = subject_public_key_info.subject_public_key.clone();
//             let jwk = Jwk::from_ec_public_key(&ec_public_key);
//             Box::new(jwk)
//         }
//         _ => Err(FederationError::UnsupportedAlgorithm),
//     }
//     todo! {};
// }
