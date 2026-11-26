pub mod json_ld;
pub mod ldp;
pub mod w3c;

#[derive(Debug, uniffi::Error)]
pub enum SigningError {
    FailedToSign,
    InvalidSecret,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

impl std::error::Error for SigningError {}

/// A signer callback owned by this dynamic library.
#[uniffi::export(with_foreign)]
pub trait SignatureCreator: Send + Sync {
    fn alg(&self) -> String;
    fn sign(&self, bytes: Vec<u8>) -> Result<Vec<u8>, SigningError>;
}

/// Replaces this native component's additional illegal and undisclosable SD-JWT claim lists.
#[cfg_attr(
    feature = "uniffi",
    uniffi::export(default(illegal_claims), default(undisclosable_claims))
)]
pub fn register_invalid_and_undisclosable_claims(
    illegal_claims: Vec<String>,
    undisclosable_claims: Vec<String>,
) {
    kapun_dcql_sdjwt_rust::sdjwt::register_invalid_and_undisclosable_claims(
        illegal_claims,
        undisclosable_claims,
    );
}

#[cfg(target_arch = "arm")]
#[used]
static _KEEP_EH_FRAME_STUBS: [unsafe extern "C" fn(); 2] = [
    kapun_util_rust::__register_frame,
    kapun_util_rust::__deregister_frame,
];

uniffi::setup_scaffolding!();
