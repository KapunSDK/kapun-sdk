mod revocation;
mod validation;
pub use revocation::validate_chain_crls_with;
use validation::{
    ChainChecks, ConstraintCheck, RootSignature, StructureCheck, validate_chain_inner,
};
pub use validation::{
    ChainEnd, ChainKind, ChainPolicy, IssuerUsage, ValidationError, has_self_signature,
    is_self_issued, is_valid_at, validate_chain_with,
};

use kapun_crypto_provider::KapunCryptoProvider;
use whitespace_sifter::WhitespaceSifter;
use x509_parser::{
    prelude::{
        ParsedExtension, TbsCertificateStructureValidator, Validator, VecLogger,
        X509ExtensionsValidator,
    },
    time::ASN1Time,
    x509::X509Name,
};

use crate::{X509Error, crypto::verify_signature, parse_certificate};

/// Provider-backed offline validation with explicit CRLs and chain policy.
pub fn validate_chain_crls<Provider: KapunCryptoProvider>(
    chain: &[Vec<u8>],
    policy: &ChainPolicy,
    crls: &[Vec<u8>],
) -> Result<(), ValidationError> {
    validate_chain_crls_with(
        chain,
        policy,
        crls,
        |issuer, subject, _| {
            verify_signature::<Provider>(issuer, subject).map_err(|e| format!("{e:?}"))
        },
        |issuer, crl| {
            crate::crypto::verify_crl::<Provider>(issuer, crl).map_err(|e| format!("{e:?}"))
        },
    )
}

pub fn select_root<T: AsRef<[u8]>>(cert: T, root_store: &Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let cert = parse_certificate(cert.as_ref()).ok()?;
    for c in root_store {
        let Ok(root) = parse_certificate(c.as_slice()) else {
            continue;
        };
        if are_x509_name_equal(&cert.issuer, &root.subject) {
            return Some(c.clone());
        }
    }
    None
}

pub fn complete_simple_chain<Provider: KapunCryptoProvider>(
    chain: &mut Vec<Vec<u8>>,
    trust_store: &Vec<Vec<u8>>,
) -> Result<(), X509Error> {
    let Some(last_element) = chain.last() else {
        return Err(X509Error::EmptyChain);
    };
    if is_valid_ca::<_, Provider>(last_element) {
        return Ok(());
    }
    let Some(root) = select_root(last_element.as_slice(), &trust_store) else {
        return Err(X509Error::X509TrustError(crate::TrustError::NoRootFound));
    };
    chain.push(root);
    Ok(())
}

/// This function checks integrity of a self signed certificate used to sign
/// user signatures. If Basic Constraint is available it MUST be false
pub fn is_self_signed_user_cert<T: AsRef<[u8]>, Provider: KapunCryptoProvider>(cert: T) -> bool {
    check_self_signed::<_, Provider>(cert, CertificateRole::Leaf, ExtensionPresence::Optional)
}
/// This function checks, if the provided certificate is a valid CA (BasicConstrain cA = true).
/// A CA MUST have the Basic Constraint extension!
pub fn is_valid_ca<T: AsRef<[u8]>, Provider: KapunCryptoProvider>(cert: T) -> bool {
    check_self_signed::<_, Provider>(
        cert,
        CertificateRole::Authority,
        ExtensionPresence::Required,
    )
}

fn check_self_signed<T: AsRef<[u8]>, Provider: KapunCryptoProvider>(
    cert: T,
    role: CertificateRole,
    presence: ExtensionPresence,
) -> bool {
    let Ok(issuer_cert) = parse_certificate(cert.as_ref()) else {
        return false;
    };
    let mut logger = VecLogger::default();
    let structure_validity = TbsCertificateStructureValidator.validate(&issuer_cert, &mut logger);
    let x509_extensions_validity =
        X509ExtensionsValidator.validate(&issuer_cert.extensions(), &mut logger);
    if !(structure_validity && x509_extensions_validity) {
        tracing::error!("structure_validity: {structure_validity}");
        tracing::error!("x509_extensions_validity: {x509_extensions_validity}");
        tracing::error!("subject cert has invalid structure");
        tracing::error!("{:?}", logger);
        return false;
    }
    if !is_key_usage_correct(&issuer_cert, IssuerUsage::IfPresent) {
        tracing::error!("issuer cert has incorrect key usage");
        return false;
    }

    let is_valid = has_self_signature(&issuer_cert, |cert| {
        verify_signature::<Provider>(cert, cert)
    })
    .unwrap_or(false);
    if !is_valid {
        tracing::error!("signature invalid");
        return false;
    }
    #[cfg(feature = "crl")]
    match check_revocation(&issuer_cert) {
        // certificate is revoked (on the CRL)
        Ok(true) => return false,
        // something went wrong
        Err(_) => return false,
        // network error or not on the list
        _ => {}
    }
    match is_basic_constraint_fulfilled(&issuer_cert, 0, role, presence) {
        Ok(fulfilled) => fulfilled,
        Err(_) => false,
    }
}

pub fn verify_chain_at_with_trust_anchors<Provider: KapunCryptoProvider>(
    certs: Vec<Vec<u8>>,
    time: ASN1Time,
    #[cfg(feature = "crl")] check_crl: bool,
    check_basic_constraint: bool,
    trust_store: Option<&Vec<Vec<u8>>>,
) -> bool {
    let end = if trust_store.is_some() {
        ChainEnd::Trusted
    } else {
        ChainEnd::Complete
    };
    let policy = ChainPolicy {
        kind: ChainKind::Signing,
        end,
        issuer_usage: IssuerUsage::IfPresent,
        time: time.timestamp(),
        trusted_anchors: trust_store.cloned().unwrap_or_default(),
        expected_spki: None,
    };
    let checks = ChainChecks {
        constraints: if check_basic_constraint {
            ConstraintCheck::Required
        } else {
            ConstraintCheck::Unchecked
        },
        structure: StructureCheck::Required,
        root_signature: RootSignature::UnlessTrusted,
        minimum_length: 2,
    };
    let verify = |issuer: &x509_parser::prelude::X509Certificate,
                  subject: &x509_parser::prelude::X509Certificate,
                  _: &[u8]| {
        verify_signature::<Provider>(issuer, subject).map_err(|e| format!("{e:?}"))?;
        #[cfg(feature = "crl")]
        if check_crl
            && (matches!(check_revocation(subject), Ok(true) | Err(_))
                || matches!(check_revocation(issuer), Ok(true) | Err(_)))
        {
            return Err("Certificate revocation check failed".into());
        }
        Ok(())
    };
    if validate_chain_inner(&certs, &policy, &checks, &verify).is_err() {
        return false;
    }

    // Preserve the legacy self-signed root check, including its CRL policy.
    if matches!(end, ChainEnd::Complete)
        && !certs
            .last()
            .is_some_and(|root| is_valid_ca::<_, Provider>(root))
    {
        return false;
    }
    true
}

pub fn verify_chain_at<Provider: KapunCryptoProvider>(
    certs: Vec<Vec<u8>>,
    time: ASN1Time,
    #[cfg(feature = "crl")] check_crl: bool,
    check_basic_constraint: bool,
) -> bool {
    verify_chain_at_with_trust_anchors::<Provider>(
        certs,
        time,
        #[cfg(feature = "crl")]
        check_crl,
        check_basic_constraint,
        None,
    )
}

pub fn verify_chain<Provider: KapunCryptoProvider>(certs: Vec<Vec<u8>>) -> bool {
    verify_chain_at::<Provider>(
        certs,
        ASN1Time::now(),
        #[cfg(feature = "crl")]
        true,
        true,
    )
}

pub fn verify_chain_with_trust_anchor<Provider: KapunCryptoProvider>(
    certs: Vec<Vec<u8>>,
    trust_anchors: Vec<Vec<u8>>,
) -> bool {
    verify_chain_at_with_trust_anchors::<Provider>(
        certs,
        ASN1Time::now(),
        #[cfg(feature = "crl")]
        true,
        true,
        Some(&trust_anchors),
    )
}

pub fn is_key_usage_correct(
    cert: &x509_parser::prelude::X509Certificate,
    policy: IssuerUsage,
) -> bool {
    if matches!(policy, IssuerUsage::Unchecked) {
        return true;
    }
    let Ok(key_usage) = cert.key_usage() else {
        return false;
    };
    match key_usage {
        Some(usage) => usage.value.key_cert_sign(),
        None => matches!(policy, IssuerUsage::IfPresent),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CertificateRole {
    Authority,
    Leaf,
}
#[derive(Clone, Copy, Debug)]
pub enum ExtensionPresence {
    Required,
    Optional,
}

pub fn basic_constraints<'a>(
    cert: &'a x509_parser::prelude::X509Certificate<'_>,
) -> Result<Option<&'a x509_parser::extensions::BasicConstraints>, ()> {
    use x509_parser::der_parser::oid;
    let Some(extension) = cert
        .get_extension_unique(&oid!(2.5.29.19))
        .map_err(|_| ())?
    else {
        return Ok(None);
    };
    match extension.parsed_extension() {
        ParsedExtension::BasicConstraints(value) => Ok(Some(value)),
        _ => Err(()),
    }
}

/// Check the role and number of subordinate, non-self-issued CAs.
pub fn is_basic_constraint_fulfilled(
    cert: &x509_parser::prelude::X509Certificate,
    depth: usize,
    role: CertificateRole,
    presence: ExtensionPresence,
) -> Result<bool, ()> {
    let Some(constraints) = basic_constraints(cert)? else {
        return Ok(matches!(presence, ExtensionPresence::Optional));
    };
    let authority = matches!(role, CertificateRole::Authority);
    if constraints.ca != authority {
        return Ok(false);
    }
    Ok(!authority
        || constraints
            .path_len_constraint
            .is_none_or(|limit| depth <= limit as usize))
}

/// Compare RDN groups, including attribute OIDs, with normalized textual values.
pub fn are_x509_name_equal(left: &X509Name, right: &X509Name) -> bool {
    use x509_parser::x509::AttributeTypeAndValue;
    let canonical = |name: &X509Name| {
        name.iter_rdn()
            .map(|rdn| {
                let mut values: Vec<_> = rdn
                    .iter()
                    .map(|value: &AttributeTypeAndValue| {
                        let text = value.as_str().ok().map(|v| v.sift().to_lowercase());
                        let tag = if text.is_some() {
                            None
                        } else {
                            Some(value.attr_value().tag().0)
                        };
                        let raw = if text.is_some() {
                            Vec::new()
                        } else {
                            value.as_slice().to_vec()
                        };
                        (value.attr_type().to_id_string(), text, tag, raw)
                    })
                    .collect();
                values.sort();
                values
            })
            .collect::<Vec<_>>()
    };
    canonical(left) == canonical(right)
}

pub fn get_crl_uri(cert: &x509_parser::prelude::X509Certificate) -> Result<Option<String>, ()> {
    // log_debug!("X509", "checking revocation");
    // We have a parse error, return err

    use x509_parser::{
        der_parser::oid,
        prelude::{DistributionPointName, GeneralName},
    };
    let Ok(maybe_dist_points) = cert.get_extension_unique(&oid!(2.5.29.31)) else {
        return Err(());
    };
    // It was parsed successfully but no CRL found
    let Some(crl_distribution_points) = maybe_dist_points else {
        return Ok(None);
    };
    // Something is terribly wrong, as we should have matched to the OID before
    let ParsedExtension::CRLDistributionPoints(dist_points) =
        crl_distribution_points.parsed_extension()
    else {
        return Err(());
    };
    // We only look at the first point
    if dist_points.points.len() > 1 {
        tracing::warn!("MORE than 1 distribution points!");
    }
    let Some(point) = dist_points.points.first() else {
        return Err(());
    };
    // The URL CRL must be in the distribution_point field
    let Some(pt) = point.distribution_point.as_ref() else {
        return Err(());
    };
    // If it is not a full name we don't know what to do
    let DistributionPointName::FullName(full_name) = pt else {
        return Err(());
    };
    // again look at the first name only
    let Some(full_name) = full_name.first() else {
        return Err(());
    };
    // we don't know how to handle CLRs that do not point towards an URL
    let GeneralName::URI(uri) = full_name else {
        return Err(());
    };
    Ok(Some(uri.to_string()))
}

#[cfg(feature = "crl")]
/// Simplified function for checking and fetching a CRL over URL
///
/// Note: *Network errors are ignored!*
pub fn check_revocation(cert: &x509_parser::prelude::X509Certificate) -> Result<bool, ()> {
    let Ok(uri) = get_crl_uri(cert) else {
        return Err(());
    };
    let Some(uri) = uri else {
        tracing::warn!("CRL no URL");
        return Ok(false);
    };
    // Fetch the revocation list using the same opt-in TLS policy as the SDK's other Rust
    // networking paths. Certificate validation remains enabled by default.
    //
    // TODO: we need to fix this in another way, as the dependency onto kapun-util introduces an unnecessary cycle
    let config = ureq::Agent::config_builder();
    // if let Some(user_agent) = kapun_util_rust::network::user_agent() {
    //     config = config.user_agent(user_agent);
    // }
    // if kapun_util_rust::network::untrusted_tls_allowed() {
    //     config = config.tls_config(
    //         ureq::tls::TlsConfig::builder()
    //             .disable_verification(true)
    //             .build(),
    //     );
    // }
    let agent = ureq::Agent::new_with_config(config.build());
    let Ok(mut response) = agent.get(&uri).call() else {
        // failed network requests are ignored
        tracing::warn!("Failed to fetch CRL");
        return Ok(false);
    };
    let b = response.body_mut();
    let Ok(list) = b.read_to_vec() else {
        // if the stream is somewhat broken, ignore!
        return Ok(false);
    };

    // we fetched something, but it fails to parse, error out
    let Ok((_, crl)) = x509_parser::parse_x509_crl(&list) else {
        tracing::error!("Resolved CRL cannot be parsed");
        return Err(());
    };

    let result = crl
        .iter_revoked_certificates()
        .find(|a| *a.serial() == cert.serial);
    tracing::info!(
        "successfully loaded CRL, revoked: {} [{}]",
        result.is_some(),
        crl.iter_revoked_certificates().count()
    );
    Ok(result.is_some())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        io::{Cursor, Read},
    };

    use flate2::read::GzDecoder;

    use josekit::jws::alg::JosekitCryptoProvider;
    use x509_parser::x509::{AttributeTypeAndValue, RelativeDistinguishedName, X509Name};
    use x509_parser::{
        der_parser::asn1_rs::{Any, Tag},
        time::ASN1Time,
    };

    use crate::x509::{is_valid_ca, verify_chain_at, verify_chain_at_with_trust_anchors};

    use super::{
        ChainEnd, ChainKind, ChainPolicy, IssuerUsage, are_x509_name_equal, validate_chain_crls,
    };

    #[test]
    /// Test if intermediate can act as an trust anchor
    fn test_intermediate_trust() {
        let valid_time = ASN1Time::from_timestamp(1790351645).unwrap();
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();
        let leaf = pem::parse(include_bytes!("../test-chains/test-trust-anchor/leaf.pem")).unwrap();
        let intermediate = pem::parse(include_bytes!(
            "../test-chains/test-trust-anchor/intermediary.pem"
        ))
        .unwrap();
        assert!(verify_chain_at_with_trust_anchors::<JosekitCryptoProvider>(
            vec![leaf.contents().to_vec()],
            valid_time,
            #[cfg(feature = "crl")]
            true,
            true,
            Some(&vec![intermediate.contents().to_vec()])
        ));
        assert!(verify_chain_at_with_trust_anchors::<JosekitCryptoProvider>(
            vec![leaf.contents().to_vec(), intermediate.contents().to_vec()],
            valid_time,
            #[cfg(feature = "crl")]
            true,
            true,
            Some(&vec![intermediate.contents().to_vec()])
        ))
    }

    #[test]
    fn test_direct_subca_anchor() {
        let valid_time = ASN1Time::from_timestamp(1790610000).unwrap();
        let leaf = pem::parse(include_bytes!("../test-chains/direct-subca/leaf.pem")).unwrap();
        let intermediate = pem::parse(include_bytes!(
            "../test-chains/direct-subca/intermediate.pem"
        ))
        .unwrap();
        let subca = pem::parse(include_bytes!("../test-chains/direct-subca/subca.pem")).unwrap();
        let root = pem::parse(include_bytes!("../test-chains/direct-subca/root.pem")).unwrap();

        let (_, leaf_cert) = x509_parser::parse_x509_certificate(leaf.contents()).unwrap();
        let (_, intermediate_cert) =
            x509_parser::parse_x509_certificate(intermediate.contents()).unwrap();
        let (_, subca_cert) = x509_parser::parse_x509_certificate(subca.contents()).unwrap();
        let (_, root_cert) = x509_parser::parse_x509_certificate(root.contents()).unwrap();

        // The trusted SubCA has a parent, but that root is absent from the supplied path.
        assert_ne!(subca_cert.subject, subca_cert.issuer);
        assert_eq!(subca_cert.issuer, root_cert.subject);
        assert_eq!(intermediate_cert.issuer, subca_cert.subject);
        assert_eq!(leaf_cert.issuer, intermediate_cert.subject);

        assert!(verify_chain_at_with_trust_anchors::<JosekitCryptoProvider>(
            vec![leaf.contents().to_vec(), intermediate.contents().to_vec()],
            valid_time,
            #[cfg(feature = "crl")]
            true,
            true,
            Some(&vec![subca.contents().to_vec()]),
        ));
    }

    #[test]
    fn test_same_subject_trust_anchors() {
        let valid_time = ASN1Time::from_timestamp(1790351645).unwrap();
        let leaf = pem::parse(include_bytes!("../test-chains/test-trust-anchor/leaf.pem")).unwrap();
        let valid = pem::parse(include_bytes!(
            "../test-chains/test-trust-anchor/intermediary.pem"
        ))
        .unwrap();
        let wrong = pem::parse(include_bytes!(
            "../test-chains/test-trust-anchor/same-subject-wrong-key.pem"
        ))
        .unwrap();

        // A matching name identifies candidates; only the signing key validates the leaf.
        for trust_store in [
            vec![wrong.contents().to_vec(), valid.contents().to_vec()],
            vec![valid.contents().to_vec(), wrong.contents().to_vec()],
        ] {
            assert!(verify_chain_at_with_trust_anchors::<JosekitCryptoProvider>(
                vec![leaf.contents().to_vec()],
                valid_time,
                #[cfg(feature = "crl")]
                true,
                true,
                Some(&trust_store),
            ));
        }

        assert!(
            !verify_chain_at_with_trust_anchors::<JosekitCryptoProvider>(
                vec![leaf.contents().to_vec()],
                valid_time,
                #[cfg(feature = "crl")]
                true,
                true,
                Some(&vec![wrong.contents().to_vec()]),
            )
        );
    }
    #[test]
    /// Test if a broken chain still fails even with trust anchors supplied
    fn test_broken_chain_is_invalid() {
        let valid_time = ASN1Time::from_timestamp(1790351645).unwrap();
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();
        let leaf = pem::parse(include_bytes!("../test-chains/test-trust-anchor/leaf.pem")).unwrap();
        let root = pem::parse(include_bytes!("../test-chains/test-trust-anchor/root.pem")).unwrap();
        assert!(
            !verify_chain_at_with_trust_anchors::<JosekitCryptoProvider>(
                vec![leaf.contents().to_vec()],
                valid_time,
                #[cfg(feature = "crl")]
                true,
                true,
                Some(&vec![root.contents().to_vec()])
            )
        )
    }

    type NistSuite = BTreeMap<String, Vec<(String, Vec<u8>)>>;

    const NIST_TIME: i64 = 1790351645;

    fn nist_suite() -> NistSuite {
        let test_suite_bytes = include_bytes!("../x509tests.tgz");
        let test_suite_bytes = GzDecoder::new(Cursor::new(test_suite_bytes));
        let mut test_suite_archive = tar::Archive::new(test_suite_bytes);
        let mut test_map = BTreeMap::<String, Vec<(String, Vec<u8>)>>::new();
        for entry in test_suite_archive.entries().unwrap() {
            let Ok(mut entry) = entry else {
                continue;
            };
            let path = entry.path().unwrap();
            if path.extension().is_some() {
                let testfile = path.strip_prefix("X509tests").unwrap();
                let test_name = testfile.parent().unwrap().to_str().unwrap().to_string();
                let file_name = testfile.file_name().unwrap().to_str().unwrap().to_string();
                let directory = test_map.entry(test_name).or_default();
                let mut file_bytes = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut file_bytes).unwrap();
                directory.push((file_name, file_bytes));
            }
        }
        test_map
    }

    #[test]
    /// Tests from https://csrc.nist.gov/Projects/pki-testing/x-509-path-validation-test-suite Version 1.07
    fn test_x509_path_validation() {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();
        let truth_table: HashMap<&str, bool> = [
            ("test1", true),
            ("test2", false),
            ("test3", false),
            ("test4", true),
            ("test5", false),
            ("test6", false),
            ("test7", true),
            ("test8", false),
            ("test9", false),
            ("test10", false),
            ("test11", false),
            ("test12", true),
            ("test13", false),
            ("test14", false),
            ("test15", true),
            ("test16", true),
            ("test17", true),
            ("test18", true),
            ("test19", false),
            ("test20", false),
            ("test21", false),
            ("test22", false),
            ("test23", false),
            ("test24", true),
            ("test25", false),
            ("test26", true),
            ("test27", true),
            ("test28", false),
            ("test29", false),
            ("test30", true),
            ("test31", false),
            ("test32", false),
            ("test33", true),
            ("test54", false),
            ("test55", false),
            ("test56", true),
            ("test57", true),
            ("test58", false),
            ("test59", false),
            ("test60", false),
            ("test61", false),
            ("test62", true),
            ("test63", true),
            ("test64", false),
            ("test65", false),
            ("test66", false),
            ("test67", true),
            ("test68", false),
            ("test69", false),
            ("test70", false),
            ("test71", false),
            ("test72", false),
            ("test73", false),
            ("test74", true),
            ("test75", false),
            ("test76", false),
        ]
        .into_iter()
        .collect();
        let test_map = nist_suite();
        let mut correct = 0;
        let mut total = 0;
        for (test, test_files) in &test_map {
            let mut certs = test_files
                .iter()
                .filter(|a| a.0.ends_with(".crt"))
                .map(|a| a.1.clone())
                .collect::<Vec<_>>();
            certs.reverse();

            let crls = test_files
                .iter()
                .filter(|(name, _)| name.ends_with(".crl"))
                .map(|(_, der)| der.clone())
                .collect::<Vec<_>>();
            let policy = ChainPolicy {
                kind: ChainKind::Signing,
                end: ChainEnd::Complete,
                issuer_usage: IssuerUsage::IfPresent,
                time: NIST_TIME,
                trusted_anchors: vec![],
                expected_spki: None,
            };
            let validation = validate_chain_crls::<JosekitCryptoProvider>(&certs, &policy, &crls);
            let result = validation.is_ok();
            let matches = if let Some(expected) = truth_table.get(&test.as_str()) {
                total += 1;
                if expected == &result {
                    correct += 1;
                    "✅"
                } else {
                    "❌"
                }
            } else {
                "-"
            };
            if truth_table
                .get(test.as_str())
                .is_some_and(|expected| *expected != result)
            {
                println!("{test}: {validation:?}");
            }
            println!(
                "{}: {} [{}] -> {matches}",
                test,
                result,
                truth_table
                    .get(&test.as_str())
                    .map(|a| a.to_string())
                    .unwrap_or("N/A".to_string())
            );
        }
        println!("{correct}/{total}");
        assert_eq!(correct, total);
    }

    #[test]
    fn test_target_ca_path_length() {
        let suite = nist_suite();
        for case in ["test57", "test63"] {
            let mut chain: Vec<_> = suite[case]
                .iter()
                .filter(|(name, _)| name.ends_with(".crt"))
                .map(|(_, der)| der.clone())
                .collect();
            chain.reverse();

            // A CA used as the target is excluded from the issuer's path length.
            assert!(
                verify_chain_at::<JosekitCryptoProvider>(
                    chain.clone(),
                    ASN1Time::from_timestamp(NIST_TIME).unwrap(),
                    #[cfg(feature = "crl")]
                    false,
                    true,
                ),
                "{case}"
            );

            // An issuing-CA chain reserves space for every subordinate CA.
            let policy = ChainPolicy {
                kind: ChainKind::Authorities,
                end: ChainEnd::Complete,
                issuer_usage: IssuerUsage::IfPresent,
                time: NIST_TIME,
                trusted_anchors: vec![],
                expected_spki: None,
            };
            assert!(
                super::validate_chain_with(&chain, &policy, |issuer, subject, _| {
                    crate::crypto::verify_signature::<JosekitCryptoProvider>(issuer, subject)
                        .map_err(|error| format!("{error:?}"))
                })
                .is_err(),
                "{case}"
            );
        }
    }

    fn make_rdn<'a>(oid_parts: &[u64], value: &'a [u8]) -> RelativeDistinguishedName<'a> {
        let oid = x509_parser::der_parser::asn1_rs::Oid::from(oid_parts)
            .unwrap()
            .to_owned();
        let any = Any::from_tag_and_data(Tag::PrintableString, value);
        RelativeDistinguishedName::new(vec![AttributeTypeAndValue::new(oid, any)])
    }

    #[test]
    fn test_name_prefix_not_equal() {
        // CN=TrustedCA, O=Corp, C=US
        let full_name = X509Name::new(
            vec![
                make_rdn(&[2, 5, 4, 3], b"TrustedCA"),
                make_rdn(&[2, 5, 4, 10], b"Corp"),
                make_rdn(&[2, 5, 4, 6], b"US"),
            ],
            &[],
        );
        // CN=TrustedCA (prefix of the above)
        let prefix_name = X509Name::new(vec![make_rdn(&[2, 5, 4, 3], b"TrustedCA")], &[]);

        assert!(!are_x509_name_equal(&prefix_name, &full_name));
        assert!(!are_x509_name_equal(&full_name, &prefix_name));
    }

    #[test]
    fn test_name_equal() {
        let name_a = X509Name::new(
            vec![
                make_rdn(&[2, 5, 4, 3], b"TrustedCA"),
                make_rdn(&[2, 5, 4, 10], b"Corp"),
            ],
            &[],
        );
        let name_b = X509Name::new(
            vec![
                make_rdn(&[2, 5, 4, 3], b"TrustedCA"),
                make_rdn(&[2, 5, 4, 10], b"Corp"),
            ],
            &[],
        );
        assert!(are_x509_name_equal(&name_a, &name_b));
    }

    #[test]
    fn test_empty_name_not_equal_to_nonempty() {
        let empty = X509Name::new(vec![], &[]);
        let nonempty = X509Name::new(vec![make_rdn(&[2, 5, 4, 3], b"TrustedCA")], &[]);

        assert!(!are_x509_name_equal(&empty, &nonempty));
        assert!(!are_x509_name_equal(&nonempty, &empty));
    }
    #[test]
    fn test_chains() {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();
        let pems = pem::parse_many(include_str!("../test-chains/google.ch")).unwrap();
        let mut chain = pems
            .into_iter()
            .map(|a| a.contents().to_vec())
            .collect::<Vec<_>>();
        chain.reverse();
        assert!(verify_chain_at::<JosekitCryptoProvider>(
            chain,
            ASN1Time::from_timestamp(1776845275).unwrap(),
            #[cfg(feature = "crl")]
            true,
            true
        ));
        let pems = pem::parse_many(include_str!("../test-chains/schweizmobil.ch")).unwrap();
        let mut chain = pems
            .into_iter()
            .map(|a| a.contents().to_vec())
            .collect::<Vec<_>>();
        chain.reverse();
        assert!(verify_chain_at::<JosekitCryptoProvider>(
            chain,
            ASN1Time::from_timestamp(1776845275).unwrap(),
            #[cfg(feature = "crl")]
            true,
            true,
        ));
    }
    #[test]
    fn test_mldsa_cert() {
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();
        let pem = pem::parse(include_str!("../test-chains/mldsa-cert.crt")).unwrap();

        assert!(is_valid_ca::<_, JosekitCryptoProvider>(pem.contents()));
    }
}
