pub mod open_badges;

#[doc(hidden)]
#[inline(never)]
pub fn uniffi_link_anchor() -> u8 {
    2
}

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

#[cfg(target_arch = "arm")]
#[used]
static _KEEP_EH_FRAME_STUBS: [unsafe extern "C" fn(); 2] = [
    kapun_util_rust::__register_frame,
    kapun_util_rust::__deregister_frame,
];

uniffi::setup_scaffolding!();
