use std::sync::{Arc, LazyLock, Mutex};

use crate::models::Credential;
use kapun_util_rust::log_error;

/// Parsers registered with the DCQL runtime by credential-format libraries.
pub(crate) static REGISTERED_PARSERS: LazyLock<Mutex<Vec<Arc<dyn CredentialParser>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

#[uniffi::export(with_foreign)]
/// Converts a serialized credential into the format-neutral DCQL representation.
pub trait CredentialParser: Send + Sync {
    /// A stable identifier used to avoid registering the same parser twice.
    fn id(&self) -> String;
    fn from_str(&self, credential: String) -> Option<Credential>;
}

impl PartialEq for dyn CredentialParser {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

#[uniffi::export]
/// Registers a credential-format parser with the DCQL runtime.
pub fn register_parser(parser: Arc<dyn CredentialParser>) {
    let Ok(mut parsers) = REGISTERED_PARSERS.lock() else {
        log_error!("DCQL", "Failed to register parser");
        return;
    };
    if !parsers.contains(&parser) {
        parsers.push(parser);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kapun_credential_core_rust::claims_pointer::Selector;
    use kapun_util_rust::value::Value;

    use crate::{
        models::{CredentialLike, Meta},
        MetaMismatch,
    };

    use super::*;

    #[derive(Debug)]
    struct TestCredential(String);

    impl CredentialLike for TestCredential {
        fn get_body(&self) -> Value {
            Value::String(self.0.clone())
        }

        fn serialize(&self) -> String {
            self.0.clone()
        }

        fn format_specifiers(&self) -> Vec<String> {
            vec!["test".to_string()]
        }

        fn matches_meta(&self, _meta: Option<Meta>) -> Option<MetaMismatch> {
            None
        }

        fn get(self: Arc<Self>, _selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
            None
        }
    }

    struct TestParser;

    impl CredentialParser for TestParser {
        fn id(&self) -> String {
            "dcql-test-parser".to_string()
        }

        fn from_str(&self, credential: String) -> Option<Credential> {
            (credential == "test-credential")
                .then(|| Credential::Other(Arc::new(TestCredential(credential))))
        }
    }

    #[test]
    fn registration_is_idempotent_and_drives_parsing() {
        register_parser(Arc::new(TestParser));
        register_parser(Arc::new(TestParser));

        let matching_parser_count = REGISTERED_PARSERS
            .lock()
            .unwrap()
            .iter()
            .filter(|parser| parser.id() == "dcql-test-parser")
            .count();
        assert_eq!(matching_parser_count, 1);

        let credential = crate::parse_credential("test-credential".to_string()).unwrap();
        let Credential::Other(credential) = credential else {
            panic!("test parser returned the wrong credential variant");
        };
        assert_eq!(credential.serialize(), "test-credential");
    }
}
