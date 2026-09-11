pub mod sdjwt;
pub mod sdjwt_util;

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
///
/// Callback vtables are local to the UniFFI component that invokes them. Keeping this interface
/// here ensures its vtable is initialized in the same shared library as `SdJwtBuilder::build`.
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

/// This crate compiles to its own native library, statically linking a private copy of
/// `kapun_util_rust::log` - registering a sink via `kapun-util`'s own binding only reaches
/// *that* library, not this one's `log_debug!` call sites. This forwards to this crate's own
/// linked-in copy of the same registration function, so a host app can reach it too. See
/// `kapun-util/rust/src/log.rs` for the full explanation.
#[uniffi::export]
pub fn register_log_sink(sink: std::sync::Arc<dyn kapun_util_rust::log::LogSink>) {
    kapun_util_rust::log::register_log_sink(sink);
}

#[uniffi::export]
pub fn clear_log_sink() {
    kapun_util_rust::log::clear_log_sink();
}

uniffi::setup_scaffolding!();
