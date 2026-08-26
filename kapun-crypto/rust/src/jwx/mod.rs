/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use josekit::{
    Map, Value,
    jwe::{JweDecrypter, JweEncrypter, JweHeader},
    jwk::{Jwk, JwkSet},
    jwt::{self, JwtPayload},
};
use kapun_util_rust::{log_warn, value::Value as KapunValue};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, uniffi::Error)]
pub enum JweError {
    InvalidParameters { reason: String },
    OperationFailed { reason: String },
}

impl std::fmt::Display for JweError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParameters { reason } | Self::OperationFailed { reason } => {
                f.write_str(reason)
            }
        }
    }
}

impl std::error::Error for JweError {}

#[derive(Debug, Clone, uniffi::Record)]
pub struct JweKey {
    pub private_jwk: String,
    pub public_jwk: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct JweHeaderParameters {
    pub algorithm: String,
    pub content_encryption: String,
    pub key_id: Option<String>,
    pub compression: Option<String>,
    pub token_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionParameters {
    pub jwk: Jwk,
    pub authorization_encrytped_response_alg: String,
    pub authorization_encrypted_response_enc: String,
}

impl EncryptionParameters {
    pub fn new_encryptor(jwk: Jwk, enc: &str) -> Option<Self> {
        let alg = jwk.algorithm()?.to_string();
        Some(Self {
            jwk,
            authorization_encrytped_response_alg: alg,
            authorization_encrypted_response_enc: enc.to_string(),
        })
    }

    pub fn new_decryptor(alg: &str, enc: &str) -> Option<Self> {
        let mut jwk = match alg {
            "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
                josekit::jwe::ECDH_ES
                    .generate_ec_key_pair(josekit::jwk::alg::ec::EcCurve::P256)
                    .ok()?
                    .to_jwk_key_pair()
            }
            "RSA1_5" =>
            {
                #[allow(deprecated)]
                josekit::jwe::RSA1_5
                    .generate_key_pair(2048)
                    .ok()?
                    .to_jwk_key_pair()
            }
            "RSA-OAEP" => josekit::jwe::RSA_OAEP
                .generate_key_pair(2048)
                .ok()?
                .to_jwk_key_pair(),
            "RSA-OAEP-256" => josekit::jwe::RSA_OAEP_256
                .generate_key_pair(2048)
                .ok()?
                .to_jwk_key_pair(),
            _ => return None,
        };
        let mut key_id = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut key_id);
        jwk.set_algorithm(alg);
        jwk.set_key_use("enc");
        jwk.set_key_id(BASE64_URL_SAFE_NO_PAD.encode(key_id));
        Some(Self {
            jwk,
            authorization_encrytped_response_alg: alg.to_string(),
            authorization_encrypted_response_enc: enc.to_string(),
        })
    }

    pub fn decrypt(&self, payload: &str) -> Result<(JwtPayload, JweHeader), JweError> {
        let header = parse_jwe_header_internal(payload)?;
        if header.algorithm.as_str() != self.authorization_encrytped_response_alg
            || header.content_encryption.as_str() != self.authorization_encrypted_response_enc
        {
            return Err(invalid(
                "JWE alg or enc does not match the configured parameters",
            ));
        }
        let decrypter = decrypter(&self.jwk, &self.authorization_encrytped_response_alg)?;
        jwt::decode_with_decrypter(payload, decrypter.as_ref())
            .map_err(|error| operation(format!("Failed to decrypt JWE: {error}")))
    }

    pub fn public_jwk(&self) -> Result<Jwk, JweError> {
        public_jwk(&self.jwk)
    }

    pub fn encrypt(
        &self,
        claims: Map<String, Value>,
        apu: Option<Vec<u8>>,
        apv: Option<Vec<u8>>,
        token_type: Option<&str>,
    ) -> Result<String, JweError> {
        self.encrypt_with_options(claims, apu, apv, token_type, None)
    }

    pub fn encrypt_with_options(
        &self,
        claims: Map<String, Value>,
        apu: Option<Vec<u8>>,
        apv: Option<Vec<u8>>,
        token_type: Option<&str>,
        compression: Option<&str>,
    ) -> Result<String, JweError> {
        let mut header = JweHeader::new();
        header.set_token_type(token_type.unwrap_or("JWT"));
        header.set_content_encryption(self.authorization_encrypted_response_enc.clone());
        header.set_algorithm(self.authorization_encrytped_response_alg.clone());
        if let Some(key_id) = self.jwk.key_id() {
            header.set_key_id(key_id);
        }
        if let Some(compression) = compression {
            if compression != "DEF" {
                return Err(invalid(format!(
                    "Unsupported JWE compression: {compression}"
                )));
            }
            header.set_compression(compression);
        }
        match (apu, apv) {
            (Some(apu), Some(apv)) => {
                header.set_agreement_partyuinfo(apu);
                header.set_agreement_partyvinfo(apv);
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "apu and apv must either both be present or both be absent",
                ));
            }
        }

        log_warn!("JWE", &self.authorization_encrypted_response_enc);
        log_warn!("JWE", &self.authorization_encrytped_response_alg);
        let payload = JwtPayload::from_map(claims)
            .map_err(|error| invalid(format!("Invalid JWE JSON payload: {error}")))?;
        let encrypter = encrypter(&self.jwk, &self.authorization_encrytped_response_alg)?;
        jwt::encode_with_encrypter(&payload, &header, encrypter.as_ref())
            .map_err(|error| operation(format!("Failed to encrypt JWE: {error}")))
    }
}

impl TryFrom<&KapunValue> for EncryptionParameters {
    type Error = JweError;

    fn try_from(value: &KapunValue) -> Result<Self, Self::Error> {
        let jwks: serde_json::Value = value
            .get("jwks")
            .ok_or_else(|| invalid("No jwks in encryption metadata"))?
            .to_owned()
            .transform()
            .ok_or_else(|| invalid("Failed to transform jwks"))?;
        let jwks = JwkSet::from_map(
            jwks.as_object()
                .ok_or_else(|| invalid("jwks is not a JSON object"))?
                .clone(),
        )
        .map_err(|error| invalid(format!("Invalid jwks: {error}")))?;
        let jwk = jwks
            .keys()
            .into_iter()
            .find(|key| key.is_for_key_operation("enc"))
            .ok_or_else(|| invalid("No encryption key in jwks"))?
            .to_owned();
        let jwk_alg = jwk.algorithm().unwrap_or("ECDH-ES");
        let (alg, enc) = match (
            value
                .get("authorization_encrypted_response_alg")
                .and_then(|value| value.as_str()),
            value
                .get("authorization_encrypted_response_enc")
                .and_then(|value| value.as_str()),
        ) {
            (None, None) => (jwk_alg.to_string(), "A256GCM".to_string()),
            (Some(alg), Some(enc)) => (alg.to_string(), enc.to_string()),
            _ => return Err(invalid("Incompatible encryption algorithms")),
        };
        Ok(Self {
            jwk,
            authorization_encrytped_response_alg: alg,
            authorization_encrypted_response_enc: enc,
        })
    }
}

#[uniffi::export]
pub fn generate_jwe_key(algorithm: String) -> Result<JweKey, JweError> {
    if algorithm == "RSA1_5" {
        return Err(invalid(
            "RSA1_5 is deprecated and cannot be used to generate new JWE keys",
        ));
    }
    let parameters = EncryptionParameters::new_decryptor(&algorithm, "A256GCM")
        .ok_or_else(|| invalid(format!("Unsupported JWE algorithm: {algorithm}")))?;
    let public_jwk = parameters.public_jwk()?;
    Ok(JweKey {
        private_jwk: parameters.jwk.to_string(),
        public_jwk: public_jwk.to_string(),
        algorithm,
    })
}

#[uniffi::export]
pub fn public_jwe_jwk(jwk_json: String) -> Result<String, JweError> {
    public_jwk(&parse_jwk(&jwk_json)?).map(|jwk| jwk.to_string())
}

#[uniffi::export]
pub fn parse_jwe_header(compact_jwe: String) -> Result<JweHeaderParameters, JweError> {
    parse_jwe_header_internal(&compact_jwe)
}

#[uniffi::export]
pub fn encrypt_jwe(
    jwk_json: String,
    payload_json: String,
    content_encryption: String,
    apu: Option<Vec<u8>>,
    apv: Option<Vec<u8>>,
    token_type: Option<String>,
    compression: Option<String>,
) -> Result<String, JweError> {
    let jwk = parse_jwk(&jwk_json)?;
    let parameters = EncryptionParameters::new_encryptor(jwk, &content_encryption)
        .ok_or_else(|| invalid("The JWK must contain an alg parameter"))?;
    let claims: Map<String, Value> = serde_json::from_str(&payload_json)
        .map_err(|error| invalid(format!("JWE payload must be a JSON object: {error}")))?;
    parameters.encrypt_with_options(
        claims,
        apu,
        apv,
        token_type.as_deref(),
        compression.as_deref(),
    )
}

#[uniffi::export]
pub fn decrypt_jwe(jwk_json: String, compact_jwe: String) -> Result<String, JweError> {
    let jwk = parse_jwk(&jwk_json)?;
    let header = parse_jwe_header_internal(&compact_jwe)?;
    let parameters = EncryptionParameters {
        jwk,
        authorization_encrytped_response_alg: header.algorithm,
        authorization_encrypted_response_enc: header.content_encryption,
    };
    let (payload, _) = parameters.decrypt(&compact_jwe)?;
    serde_json::to_string(payload.as_ref()).map_err(|error| {
        operation(format!(
            "Failed to serialize decrypted JWE payload: {error}"
        ))
    })
}

fn parse_jwk(value: &str) -> Result<Jwk, JweError> {
    Jwk::from_bytes(value.as_bytes()).map_err(|error| invalid(format!("Invalid JWK: {error}")))
}

fn public_jwk(jwk: &Jwk) -> Result<Jwk, JweError> {
    let mut public = jwk
        .to_public_key()
        .map_err(|error| operation(format!("Failed to derive public JWK: {error}")))?;
    if let Some(key_id) = jwk.key_id() {
        public.set_key_id(key_id);
    }
    Ok(public)
}

fn parse_jwe_header_internal(payload: &str) -> Result<JweHeaderParameters, JweError> {
    let header = jwt::decode_header(payload)
        .map_err(|error| invalid(format!("Invalid compact JWE: {error}")))?;
    let header = header
        .as_any()
        .downcast_ref::<JweHeader>()
        .ok_or_else(|| invalid("The token is not a JWE"))?;
    Ok(JweHeaderParameters {
        algorithm: header
            .algorithm()
            .ok_or_else(|| invalid("JWE header has no alg"))?
            .to_string(),
        content_encryption: header
            .content_encryption()
            .ok_or_else(|| invalid("JWE header has no enc"))?
            .to_string(),
        key_id: header.key_id().map(str::to_string),
        compression: header.compression().map(str::to_string),
        token_type: header.token_type().map(str::to_string),
    })
}

fn decrypter(jwk: &Jwk, algorithm: &str) -> Result<Box<dyn JweDecrypter>, JweError> {
    let result: Result<Box<dyn JweDecrypter>, josekit::JoseError> = match algorithm {
        "ECDH-ES" => josekit::jwe::ECDH_ES
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "ECDH-ES+A128KW" => josekit::jwe::ECDH_ES_A128KW
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "ECDH-ES+A192KW" => josekit::jwe::ECDH_ES_A192KW
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "ECDH-ES+A256KW" => josekit::jwe::ECDH_ES_A256KW
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "RSA1_5" =>
        {
            #[allow(deprecated)]
            josekit::jwe::RSA1_5
                .decrypter_from_jwk(jwk)
                .map(|value| Box::new(value) as Box<dyn JweDecrypter>)
        }
        "RSA-OAEP" => josekit::jwe::RSA_OAEP
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "RSA-OAEP-256" => josekit::jwe::RSA_OAEP_256
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "A128KW" => josekit::jwe::A128KW
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "A192KW" => josekit::jwe::A192KW
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        "A256KW" => josekit::jwe::A256KW
            .decrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweDecrypter>),
        _ => return Err(invalid(format!("Unsupported JWE algorithm: {algorithm}"))),
    };
    result.map_err(|error| invalid(format!("JWK is incompatible with {algorithm}: {error}")))
}

fn encrypter(jwk: &Jwk, algorithm: &str) -> Result<Box<dyn JweEncrypter>, JweError> {
    let result: Result<Box<dyn JweEncrypter>, josekit::JoseError> = match algorithm {
        "ECDH-ES" => josekit::jwe::ECDH_ES
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "ECDH-ES+A128KW" => josekit::jwe::ECDH_ES_A128KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "ECDH-ES+A192KW" => josekit::jwe::ECDH_ES_A192KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "ECDH-ES+A256KW" => josekit::jwe::ECDH_ES_A256KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "RSA1_5" =>
        {
            #[allow(deprecated)]
            josekit::jwe::RSA1_5
                .encrypter_from_jwk(jwk)
                .map(|value| Box::new(value) as Box<dyn JweEncrypter>)
        }
        "RSA-OAEP" => josekit::jwe::RSA_OAEP
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "RSA-OAEP-256" => josekit::jwe::RSA_OAEP_256
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "A128KW" => josekit::jwe::A128KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "A192KW" => josekit::jwe::A192KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        "A256KW" => josekit::jwe::A256KW
            .encrypter_from_jwk(jwk)
            .map(|value| Box::new(value) as Box<dyn JweEncrypter>),
        _ => return Err(invalid(format!("Unsupported JWE algorithm: {algorithm}"))),
    };
    result.map_err(|error| invalid(format!("JWK is incompatible with {algorithm}: {error}")))
}

fn invalid(reason: impl Into<String>) -> JweError {
    JweError::InvalidParameters {
        reason: reason.into(),
    }
}

fn operation(reason: impl Into<String>) -> JweError {
    JweError::OperationFailed {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_round_trip_with_compression() {
        let key = generate_jwe_key("ECDH-ES+A256KW".to_string()).unwrap();
        let encrypted = encrypt_jwe(
            key.public_jwk,
            r#"{"credential":"example"}"#.to_string(),
            "A256GCM".to_string(),
            None,
            None,
            Some("JWT".to_string()),
            Some("DEF".to_string()),
        )
        .unwrap();
        let header = parse_jwe_header(encrypted.clone()).unwrap();
        assert_eq!(header.algorithm, "ECDH-ES+A256KW");
        assert_eq!(header.compression.as_deref(), Some("DEF"));
        assert_eq!(
            decrypt_jwe(key.private_jwk, encrypted).unwrap(),
            r#"{"credential":"example"}"#
        );
    }

    #[test]
    fn rsa_round_trip() {
        let key = generate_jwe_key("RSA-OAEP-256".to_string()).unwrap();
        let encrypted = encrypt_jwe(
            key.public_jwk,
            r#"{"transaction_id":"123"}"#.to_string(),
            "A128CBC-HS256".to_string(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            decrypt_jwe(key.private_jwk, encrypted).unwrap(),
            r#"{"transaction_id":"123"}"#
        );
    }

    #[test]
    fn rsa1_5_key_generation_is_rejected() {
        let error = generate_jwe_key("RSA1_5".to_string()).unwrap_err();
        assert!(error.to_string().contains("deprecated"));
    }

    #[test]
    fn decrypts_nimbus_rsa_oaep_256_vector() {
        let private_jwk = r#"{"p":"wkYkI2kNn7ft2fE_rkD31ZyClvMV38grI81xyLpUS75hSSK5EII_TE0eZgRhTke7DopR60qzqv8NFrGSxWrCqW9nvPC7TaMGtUHcE1jxQaXS6LQ2Sa-KDxH4F3aop_60jzM4ZMlZG6FOHPIP5PpDjME7DZOO04KS-NHQCE-JpUU","kty":"RSA","q":"wNpDJUuKXUcGA7u4YtdSzqBJfgUwJ9hqxd4QeaPnldq9N_yAG9pSgqj6kUbOM8rTXinpMctRpARp3sySmp_PHViAAdhuHSGyFmdAHKC_lMmt7ZMasvA_ZIygIIEZ275zb7QGLnmJEyi-Og_1QoGWvqtvcSz5xIySu0iJ0FdU7ns","d":"AxRZBn4MA0sm8vUR0s2hjftTzex6z6IzaMZuhJbeqwvWY7bP6UfBXYmOGuaryzc-8oob3GEkAWJauD6dcYg9DRemhkf1-yiEDs0uQGzLXrRYuxXmjG1YYKp7tQ0KSGADcLfVvrVXhshn_oWOXW7uCKFAM2wDpFJX7KJJ6rqodi8KctxpHy5T78uggh6NzJLpDLaNOBoW527o0Ryn-PYwuJgBCj_Fms5VfX4C24hwV7oH2cs0Q_qFOh7NSX0gTmQ5bPJSnG-YNn9kNRiYh-q1YOwCqdf7NBG-jdwOFRn6AM7keyElzaOrhKnh2EzrKKaHgdEYrqv7jfI_oJqBnZLeOQ","e":"AQAB","use":"enc","kid":"nimbus-vector","qi":"O9SSC7fS86vP7f9ika0s7ORMMSRGZGzfKwAZyAWbqXpGfEVZWLRaYVYVCokiN2G2Zs9oFEL_VkP6LuJyUGkpZQwsGf5Y7Jf11xyC-Zh8WrTW68gy4-NvA7aaC4GpqIMrj6JvrWb2F3qC9d_QGT1hrXzHMBYalST7iIcgmojuD4Q","dp":"o5xgqPW7RIypIoe7IqySS_LQRAIapOk186P8tJi_jz6ZPfehNdcLKd40wKPlswBT963jya2S3GqKAlewDNSZdgpdqlBu3bZzWslJZ33bSHc3xUSoB6xvL7vpXRFQfpLSS1tOngq4Ib3aRCRT4Hon022Upx1jBpwL3MMOWUFq4aU","alg":"RSA-OAEP-256","dq":"uq6NcPy-46xs1hBRXNyy-_GNMsAy7V9BfGiJ6jYPZ7BmmluCZ3Pfizun0hmIYfpkwTIw2lLGpM7g7Rt6jtND2lRhFWg8r1Z-3dD07sFsssrH4sIThkOqGdtG5jASp_SkKe1KTpK3biRygCISeF6ZXdj198hhvzGUmFaPkW34eSE","n":"klo9yf3duC_wzDWcGeN6RBvOevKVpfdIZVS1AS-SdK1I37xbWlh8P6kNovOw5UZjdtI4hpcvEJbCqeyipkam9BBD7qPI4vJNeLYf22_nZvqC9SoSoADkV2lUAl3Pn-R9oTAqzGhf0HaVbaF8v9KavlXrtExPhFwfvZRuFsFJ2ygOtgEthqNVkeZe1dJdyeWVIW8QFC1XLdMJDCFes0m-19CnCjX9gGMU6n7DOrfuhJwVa3gzZZ8O5oKLXBCLk9txO1PkbR8kPd9asfwAi9XVz13cAaJ-Bp9tO_I-fov0kbJaPj3R9_jcPZd63uPS79In2HNEO13As5bdqMNU3GyOJw"}"#;
        let compact_jwe = "eyJraWQiOiJuaW1idXMtdmVjdG9yIiwidHlwIjoiSldUIiwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IlJTQS1PQUVQLTI1NiJ9.E11VVerQlN2STFaDhE60UMbnQl0L2fhec3pxaIaTcJpx4iOuItwtLkV4_pkONmNnBhct0RgLYHrM27VhHcvPAAkjgY_rr7UvWv9UBckqThuNVmHi0QD_3eOs6Uo3vfSDEUoknigAxonaHIJlFUsYPTo_QBnDoWl_96Gmb-HuXE7pEJX0etiLUgkC-Q0xWXqaPyzKaLsig9Ee4H4V5G2Fnq7G1F93mlqoCOY0hp2Cuw-KBq5ODc8Y7vJvuGS1IoW79VSBhi7BTIL1QtnZimLacezeu9NSFpSesYGu8980kCRrsr99VCaUHBVh200BipQdYU535R0T5YeHqtE96Jiu9A.yBZxAeIMxKOH18BU.GkWif-VvD6BxxdvqzG1vOYHI6gWL4UPypumSVbGUjFME7Xc9TeCMHVq52i62.Av5oopDEpJaH-kOD5LWAiQ";

        assert_eq!(
            decrypt_jwe(private_jwk.to_string(), compact_jwe.to_string()).unwrap(),
            r#"{"iss":"nimbus","credential":"interoperable"}"#
        );
        let header = parse_jwe_header(compact_jwe.to_string()).unwrap();
        assert_eq!(header.key_id.as_deref(), Some("nimbus-vector"));
        assert_eq!(header.token_type.as_deref(), Some("JWT"));
    }

    #[test]
    fn decrypts_nimbus_ecdh_es_vector() {
        let private_jwk = r#"{"kty":"EC","d":"VgSvRcFbS5vtuJlzbeTgT_mwPRLPWtcfxY3E_crB9XI","use":"enc","crv":"P-256","kid":"nimbus-ec-vector","x":"-cICmfRWGffLkwFFNpuUPttzC9kQ_NfuX3UlsjGCz5w","y":"IFvIlSifTWcJkFEzlMsJQHn8w-F-LSz5Dv9_UcLznlQ","alg":"ECDH-ES"}"#;
        let compact_jwe = "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI0cXl4enlLVU1jREh3d1FBZENYUTBYSTZuVG5LYkhfQjZKQXU3V1dacFlVIiwieSI6IkVEaVBtYkJzdElJSk10Tm94dHZtTHBsLS1SV18zOTNjZzhmbHFHaTlZbUUifSwia2lkIjoibmltYnVzLWVjLXZlY3RvciIsImVuYyI6IkExMjhHQ00iLCJhbGciOiJFQ0RILUVTIn0..rer_AFuDut82r0tr.pSHE6anU1SeDXdYL7nGPZwNB9MvItYauQjUrPKTPCVb7.H1QRnkSmzalB_NMs15u5Hw";

        assert_eq!(
            decrypt_jwe(private_jwk.to_string(), compact_jwe.to_string()).unwrap(),
            r#"{"source":"nimbus","kind":"ecdh"}"#
        );
    }
}
