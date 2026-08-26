use kapun_crypto_provider::{Signer, Verifier};
use simple_x509::X509Builder;
use x509_parser::{der_parser::asn1_rs::FromDer, x509::SubjectPublicKeyInfo};
#[derive(Clone, Default)]
pub struct CertificateData {
    subject: SubjectIdentifier,
    issuer: SubjectIdentifier,
    not_before: i64,
    not_after: i64,
}
#[derive(Clone, Default)]
pub struct SubjectIdentifier {
    country: Option<String>,
    state: Option<String>,
    organization: Option<String>,
    locality: Option<String>,
    common_name: String,
}
#[derive(Debug)]
pub enum X509CreationError {
    NoPublicKey,
    FailedToEncodeX509,
}

pub fn create_certificate<V: Verifier, S: Signer>(
    certificate_data: &CertificateData,
    verifier: V,
    issuer_signer: S,
    is_ca: bool,
) -> Result<Vec<u8>, X509CreationError> {
    let serial: [u8; 32] = rand::random();
    let mut builder = X509Builder::new(serial.to_vec()) /* SerialNumber */
        .version(2);
    let issuer = certificate_data.issuer.clone();
    let subject = certificate_data.subject.clone();
    builder = builder.issuer_utf8(vec![2, 5, 4, 3], &issuer.common_name);
    if let Some(country) = &issuer.country {
        builder = builder.issuer_prstr(vec![2, 5, 4, 6], &country); /* countryName */
    }
    if let Some(state) = &issuer.state {
        builder = builder.issuer_utf8(vec![2, 5, 4, 8], state); /* stateOrProvinceName */
    }
    if let Some(organization) = &issuer.organization {
        builder = builder.issuer_utf8(vec![2, 5, 4, 10], &organization); /* organizationName */
    }
    builder = builder.subject_utf8(vec![2, 5, 4, 3], &subject.common_name); /* common name */

    if let Some(country) = subject.country {
        builder = builder.subject_prstr(vec![2, 5, 4, 6], &country); /* countryName */
    }
    if let Some(state) = &subject.state {
        builder = builder.subject_utf8(vec![2, 5, 4, 8], state); /* stateOrProvinceName */
    }
    if let Some(organization) = &subject.organization {
        builder = builder.subject_utf8(vec![2, 5, 4, 10], organization); /* organizationName */
    }
    if let Some(locality) = &subject.locality {
        builder = builder.subject_utf8(vec![2, 5, 4, 7], locality);
    }

    let Some(der_bytes) = verifier.kapun_public_spki_der() else {
        return Err(X509CreationError::NoPublicKey);
    };
    let Ok((_, spki)) = SubjectPublicKeyInfo::from_der(&der_bytes) else {
        return Err(X509CreationError::NoPublicKey);
    };
    let mut cert_builder = builder
        .not_before_utc(certificate_data.not_before)
        .not_after_utc(certificate_data.not_after)
        .pub_key_der(&der_bytes)
        .sign_oid(
            spki.algorithm
                .oid()
                .iter()
                .and_then(|a| Some(a.into_iter().collect::<Vec<_>>()))
                .unwrap_or_default(),
        );

    let cert = cert_builder
        .build()
        .sign(|d, _| issuer_signer.kapun_sign(d.to_vec()).ok(), &[])
        .unwrap();
    cert.x509_enc()
        .map_err(|_| X509CreationError::FailedToEncodeX509)
}

#[cfg(feature = "p12")]
pub fn encode_to_p12(
    private_key: Vec<u8>,
    cert: Vec<u8>,
    ca: Option<Vec<u8>>,
    alias: &str,
    password: &str,
) -> Option<Vec<u8>> {
    use p12::{AesCbcDataEncryptor, PFX, Pbkdf2};

    Some(
        PFX::new::<AesCbcDataEncryptor, Pbkdf2>(
            &cert,
            &private_key,
            ca.as_deref(),
            password,
            alias,
        )?
        .to_der(),
    )
}

#[cfg(test)]
#[cfg(feature = "builder")]
mod tests {
    use std::assert_eq;

    use josekit::{
        jwk::KeyPair,
        jws::alg::{
            JosekitCryptoProvider,
            eddsa::{EddsaJwsAlgorithm::Eddsa, EddsaJwsVerifier},
            ml_dsa::{MldsaJwsAlgorithm::MlDSA44, MldsaJwsSigner, MldsaJwsVerifier},
        },
    };
    use p12::PFX;

    use crate::{
        builder::{CertificateData, SubjectIdentifier, create_certificate, encode_to_p12},
        x509::verify_chain,
    };

    #[test]
    fn create_cert() {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();

        let issuer_kp = MlDSA44.generate_key_pair().unwrap();
        let leaf_kp = Eddsa
            .generate_key_pair(josekit::jwk::alg::ed::EdCurve::Ed25519)
            .unwrap();
        let cert_data = CertificateData {
            subject: SubjectIdentifier {
                country: Some("CH".into()),
                state: Some("Zurich".into()),
                common_name: "Subject".into(),
                ..Default::default()
            },
            issuer: SubjectIdentifier {
                country: Some("CH".into()),
                state: Some("Zurich".into()),
                common_name: "Issuer".into(),
                ..Default::default()
            },
            not_before: 1787209356000,
            not_after: 1987209356000,
        };
        let signer = MlDSA44
            .signer_from_der(issuer_kp.to_der_private_key())
            .unwrap();
        let verifier = Eddsa
            .verifier_from_der(leaf_kp.to_der_public_key())
            .unwrap();
        let leaf_cert = create_certificate::<EddsaJwsVerifier, MldsaJwsSigner>(
            &cert_data, verifier, signer, false,
        )
        .unwrap();

        let cert_data = CertificateData {
            subject: SubjectIdentifier {
                country: Some("CH".into()),
                state: Some("Zurich".into()),
                common_name: "Issuer".into(),
                ..Default::default()
            },
            issuer: SubjectIdentifier {
                country: Some("CH".into()),
                state: Some("Zurich".into()),
                common_name: "Issuer".into(),
                ..Default::default()
            },
            not_before: 1787209356000,
            not_after: 1987209356000,
        };
        let signer = MlDSA44
            .signer_from_der(issuer_kp.to_der_private_key())
            .unwrap();
        let verifier = MlDSA44
            .verifier_from_der(issuer_kp.to_der_public_key())
            .unwrap();
        let ca = create_certificate::<MldsaJwsVerifier, MldsaJwsSigner>(
            &cert_data, verifier, signer, true,
        )
        .unwrap();
        let chain = vec![leaf_cert, ca];
        assert!(verify_chain::<JosekitCryptoProvider>(chain))
    }
    #[test]
    #[cfg(feature = "p12")]
    fn test_p12_encoding() {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();

        let issuer_kp = MlDSA44.generate_key_pair().unwrap();
        let leaf_kp = Eddsa
            .generate_key_pair(josekit::jwk::alg::ed::EdCurve::Ed25519)
            .unwrap();
        let cert_data = CertificateData {
            subject: SubjectIdentifier {
                country: Some("CH".into()),
                state: Some("Zurich".into()),
                common_name: "Subject".into(),
                ..Default::default()
            },
            issuer: SubjectIdentifier {
                country: Some("CH".into()),
                state: Some("Zurich".into()),
                common_name: "Issuer".into(),
                ..Default::default()
            },
            not_before: 1787209356000,
            not_after: 1987209356000,
        };
        let signer = MlDSA44
            .signer_from_der(issuer_kp.to_der_private_key())
            .unwrap();
        let verifier = Eddsa
            .verifier_from_der(leaf_kp.to_der_public_key())
            .unwrap();
        let leaf_cert = create_certificate::<EddsaJwsVerifier, MldsaJwsSigner>(
            &cert_data, verifier, signer, false,
        )
        .unwrap();

        let p12_vec = encode_to_p12(
            leaf_kp.to_der_private_key(),
            leaf_cert.clone(),
            None,
            "test",
            "1234",
        )
        .unwrap();
        let p12_decoded = PFX::parse(&p12_vec).unwrap();
        let cert_bags = p12_decoded.cert_bags("1234").unwrap();
        let cert = cert_bags.first().unwrap();
        let key_bags = p12_decoded.key_bags("1234").unwrap();
        let private_key = key_bags.first().unwrap();

        assert_eq!(&leaf_cert, cert);
        assert_eq!(&leaf_kp.to_der_private_key(), private_key);
    }
}
