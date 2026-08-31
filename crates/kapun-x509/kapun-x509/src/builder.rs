use std::{str::FromStr, time::Duration};

use kapun_crypto_provider::{Signer as KapunSigner, Verifier as KapunVerifier};

use x509_cert::der::Encode;
use x509_cert::der::asn1::Ia5String;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::{
    SubjectPublicKeyInfo,
    builder::{Builder, CertificateBuilder, profile},
    der::Decode,
    name::Name,
    serial_number::SerialNumber,
    spki::{
        DynSignatureAlgorithmIdentifier, EncodePublicKey, ObjectIdentifier,
        SignatureBitStringEncoding,
    },
    time::Validity,
};

pub fn new_cert<V: KapunVerifier, S: KapunSigner + Clone>(
    pub_key: V,
    signer: S,
    subject: &str,
    issuer: Option<&str>,
    is_root: bool,
) -> Vec<u8> {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::from_hours(24 * 365)).unwrap();
    let subject = Name::from_str(subject).unwrap();
    if is_root {
        let profile = profile::cabf::Root::new(false, subject).expect("Create root profile");
        let spki =
            SubjectPublicKeyInfo::from_der(&pub_key.kapun_public_spki_der().unwrap()).unwrap();
        let cert_builder = CertificateBuilder::new(profile, serial_number, validity, spki).unwrap();

        let cert = cert_builder.build(&X509Signer(signer)).unwrap();
        cert.to_der().expect("Failed to serialize")
    } else if let Some(issuer) = issuer {
        let profile = profile::cabf::tls::Subordinate {
            issuer: Name::from_str(issuer).unwrap(),
            subject,
            path_len_constraint: None,
            emits_ocsp_response: false,
            client_auth: false,
        };
        let spki =
            SubjectPublicKeyInfo::from_der(&pub_key.kapun_public_spki_der().unwrap()).unwrap();
        let mut cert_builder =
            CertificateBuilder::new(profile, serial_number, validity, spki).unwrap();

        cert_builder
            .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                GeneralName::DnsName(Ia5String::new("https://example.com").unwrap()),
            ]))
            .unwrap();
        let cert = cert_builder.build(&X509Signer(signer)).unwrap();
        cert.to_der().expect("Failed to serialize")
    } else {
        panic!("Failed");
    }
}

#[derive(Clone)]
pub struct X509Signer<S: KapunSigner + Clone>(S);
impl<S: KapunSigner + Clone> DynSignatureAlgorithmIdentifier for X509Signer<S> {
    fn signature_algorithm_identifier(
        &self,
    ) -> x509_cert::spki::Result<x509_cert::AlgorithmIdentifier> {
        let spki = self.0.kapun_public_spki_der().unwrap();
        let spki = SubjectPublicKeyInfo::from_der(&spki).unwrap();
        signing_algorithm_from_spki(spki.algorithm)
    }
}

fn signing_algorithm_from_spki(
    algorithm: x509_cert::AlgorithmIdentifier,
) -> x509_cert::spki::Result<x509_cert::AlgorithmIdentifier> {
    const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
    const SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
    const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
    const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
    const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");
    const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
    const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
    const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

    let signature_oid = match algorithm.oid {
        EC_PUBLIC_KEY => {
            let curve = algorithm
                .parameters
                .as_ref()
                .ok_or(x509_cert::spki::Error::AlgorithmParametersMissing)?
                .decode_as::<ObjectIdentifier>()?;
            match curve {
                P256 | SECP256K1 => ECDSA_SHA256,
                P384 => ECDSA_SHA384,
                P521 => ECDSA_SHA512,
                oid => return Err(x509_cert::spki::Error::OidUnknown { oid }),
            }
        }
        // A generic RSA SPKI does not identify the hash. Use RS256 as the
        // baseline JWA algorithm until josekit exposes its signing algorithm.
        RSA_ENCRYPTION => RSA_SHA256,
        ED25519 | ED448 | ML_DSA_44 | ML_DSA_65 | ML_DSA_87 => algorithm.oid,
        _ => return Ok(algorithm),
    };

    Ok(x509_cert::AlgorithmIdentifier {
        oid: signature_oid,
        parameters: None,
    })
}

pub struct KapunSignature(Vec<u8>);
impl SignatureBitStringEncoding for KapunSignature {
    fn to_bitstring(&self) -> x509_cert::der::Result<x509_cert::der::asn1::BitString> {
        x509_cert::der::asn1::BitString::from_bytes(self.0.as_ref())
    }
}

fn ecdsa_signature_to_der(signature: &[u8]) -> Option<Vec<u8>> {
    if signature.is_empty() || signature.len() % 2 != 0 {
        return None;
    }

    fn encode_length(output: &mut Vec<u8>, length: usize) {
        if length < 128 {
            output.push(length as u8);
            return;
        }

        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        output.push(0x80 | (bytes.len() - first) as u8);
        output.extend_from_slice(&bytes[first..]);
    }

    fn encode_integer(output: &mut Vec<u8>, value: &[u8]) {
        let first = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len() - 1);
        let value = &value[first..];
        let needs_sign_padding = value[0] & 0x80 != 0;

        output.push(0x02);
        encode_length(output, value.len() + usize::from(needs_sign_padding));
        if needs_sign_padding {
            output.push(0);
        }
        output.extend_from_slice(value);
    }

    let (r, s) = signature.split_at(signature.len() / 2);
    let mut integers = Vec::with_capacity(signature.len() + 6);
    encode_integer(&mut integers, r);
    encode_integer(&mut integers, s);

    let mut der = Vec::with_capacity(integers.len() + 3);
    der.push(0x30);
    encode_length(&mut der, integers.len());
    der.extend_from_slice(&integers);
    Some(der)
}

fn is_ecdsa_signature_oid(oid: &[u8]) -> bool {
    matches!(
        oid,
        // ecdsa-with-SHA256/384/512
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02..=0x04]
    )
}

impl<S: KapunSigner + Clone> signature::Signer<KapunSignature> for X509Signer<S> {
    fn try_sign(&self, msg: &[u8]) -> Result<KapunSignature, signature::Error> {
        let signature = kapun_crypto_provider::Signing::kapun_sign(&self.0, msg.to_vec())
            .map_err(|_| signature::Error::new())?;
        let algorithm = self
            .signature_algorithm_identifier()
            .map_err(|_| signature::Error::new())?;

        if is_ecdsa_signature_oid(algorithm.oid.as_bytes()) {
            return ecdsa_signature_to_der(&signature)
                .map(KapunSignature)
                .ok_or_else(signature::Error::new);
        }

        Ok(KapunSignature(signature))
    }
}
impl<S: KapunSigner + Clone> AsRef<X509Signer<S>> for X509Signer<S> {
    fn as_ref(&self) -> &X509Signer<S> {
        &self
    }
}
impl<S: KapunSigner + Clone> signature::KeypairRef for X509Signer<S> {
    type VerifyingKey = X509Signer<S>;
}
impl<S: KapunSigner + Clone> EncodePublicKey for X509Signer<S> {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::der::Document> {
        Ok(x509_cert::der::Document::from_der(&self.0.kapun_public_spki_der().unwrap()).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use josekit::jws::alg::{
        JosekitCryptoProvider,
        ecdsa::{EcdsaJwsAlgorithm::Es256, EcdsaJwsSigner, EcdsaJwsVerifier},
    };

    use crate::builder::new_cert;

    #[test]
    fn encodes_raw_ecdsa_signature_as_der() {
        let raw = [0x00, 0x7f, 0x80, 0x01];
        let der = super::ecdsa_signature_to_der(&raw).unwrap();

        assert_eq!(
            der,
            [0x30, 0x08, 0x02, 0x01, 0x7f, 0x02, 0x03, 0x00, 0x80, 0x01]
        );
    }

    #[test]
    fn create_cert() {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        use x509_cert::der::Decode;
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();
        let signer_kp = Es256.generate_key_pair().unwrap();
        let verifier_kp = Es256.generate_key_pair().unwrap();

        let verifier = Es256
            .verifier_from_der(signer_kp.to_der_public_key())
            .unwrap();

        let signer = Es256
            .signer_from_der(signer_kp.to_der_private_key())
            .unwrap();

        let cert_root = new_cert::<EcdsaJwsVerifier, EcdsaJwsSigner>(
            verifier,
            signer,
            "CN=World domination corporation,O=World domination Inc,C=US",
            None,
            true,
        );
        let parsed_root = x509_cert::Certificate::from_der(&cert_root).unwrap();
        assert_eq!(
            parsed_root.signature_algorithm().oid,
            x509_cert::spki::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2")
        );
        assert!(parsed_root.signature_algorithm().parameters.is_none());
        let res = base64::prelude::BASE64_STANDARD_NO_PAD.encode(&cert_root);
        println!("{res}");

        let verifier = Es256
            .verifier_from_der(verifier_kp.to_der_public_key())
            .unwrap();

        let signer = Es256
            .signer_from_der(signer_kp.to_der_private_key())
            .unwrap();

        let cert = new_cert::<EcdsaJwsVerifier, EcdsaJwsSigner>(
            verifier,
            signer,
            "CN=Subordinate,O=World domination Inc,C=US",
            Some("CN=World domination corporation,O=World domination Inc,C=US"),
            false,
        );
        let chain = vec![cert.clone(), cert_root];

        assert!(crate::x509::verify_chain::<JosekitCryptoProvider>(chain));
        println!();
        let res = base64::prelude::BASE64_STANDARD_NO_PAD.encode(&cert);
        println!("{res}");
    }
}
