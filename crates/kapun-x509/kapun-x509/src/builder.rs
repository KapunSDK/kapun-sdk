use std::{str::FromStr, time::Duration};

use kapun_crypto_provider::{
    KapunCryptoProvider, Signer as KapunSigner, Verifier as KapunVerifier,
};
use simple_x509::Error::Signature;
use x509_cert::der::Encode;
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

pub fn new_cert<V: KapunVerifier, S: KapunSigner + Clone>(pub_key: V, signer: S) {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("Create root profile");
    let spki = SubjectPublicKeyInfo::from_der(&pub_key.kapun_public_spki_der().unwrap()).unwrap();
    let cert_builder = CertificateBuilder::new(profile, serial_number, validity, spki).unwrap();
    let cert = cert_builder.build(&X509Signer(signer)).unwrap();
    cert.to_der()
}

#[derive(Clone)]
pub struct X509Signer<S: KapunSigner + Clone>(S);
impl<S: KapunSigner + Clone> DynSignatureAlgorithmIdentifier for X509Signer<S> {
    fn signature_algorithm_identifier(
        &self,
    ) -> x509_cert::spki::Result<x509_cert::AlgorithmIdentifier> {
        Ok(x509_cert::AlgorithmIdentifier {
            oid: ObjectIdentifier::from_bytes(&self.0.kapun_oid().unwrap()).unwrap(),
            parameters: None,
        })
    }
}

pub struct KapunSignature(Vec<u8>);
impl SignatureBitStringEncoding for KapunSignature {
    fn to_bitstring(&self) -> x509_cert::der::Result<x509_cert::der::asn1::BitString> {
        x509_cert::der::asn1::BitString::from_bytes(self.0.as_ref())
    }
}

impl<S: KapunSigner + Clone> signature::Signer<KapunSignature> for X509Signer<S> {
    fn try_sign(&self, msg: &[u8]) -> Result<KapunSignature, signature::Error> {
        kapun_crypto_provider::Signing::kapun_sign(&self.0, msg.to_vec())
            .map(|a| KapunSignature(a))
            .map_err(|_| signature::Error::new())
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
