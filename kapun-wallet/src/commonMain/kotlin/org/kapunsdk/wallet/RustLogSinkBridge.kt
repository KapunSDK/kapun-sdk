package org.kapunsdk.wallet

import org.kapunsdk.util.log.RustToKotlinLogSink
import org.kapunsdk.util.log.bridgeRustLogsToKotlin
import uniffi.kapun_util_rust.LogPriority

/**
 * Implements each component's local callback interface. The interfaces intentionally have the
 * same method shape, but must remain distinct so every native library initializes and uses its
 * own UniFFI callback vtable.
 */
private object ComponentRustLogSink :
	uniffi.kapun_crypto_rust.LogSink,
	uniffi.kapun_issuance_rust.LogSink,
	uniffi.kapun_dcql_rust.LogSink,
	uniffi.kapun_dcql_sdjwt_rust.LogSink,
	uniffi.kapun_wallet_rust.LogSink {
	override fun log(priority: LogPriority, tag: String, message: String): Boolean =
		RustToKotlinLogSink.log(priority, tag, message)
}

/**
 * Every Rust crate that has its own `log_warn!`/`log_error!`/`log_debug!` call sites compiles to
 * its own native library, each statically linking a *private* copy of `kapun_util_rust`'s log
 * module (own copy of the sink slot, own copy of `log(...)`) - see `kapun-util/rust/src/log.rs`.
 * Registering a sink only on `kapun_util_rust`'s own binding ([bridgeRustLogsToKotlin]) therefore
 * doesn't reach any of the others; each crate below exports its own `registerLogSink` (a thin
 * forward to the same underlying function, just linked into that crate's own library) for exactly
 * this reason. Called once from each platform's `KapunSdk.initialize()`.
 */
internal fun bridgeAllRustLogSinks() {
	bridgeRustLogsToKotlin()
	uniffi.kapun_crypto_rust.registerLogSink(ComponentRustLogSink)
	uniffi.kapun_issuance_rust.registerLogSink(ComponentRustLogSink)
	uniffi.kapun_dcql_rust.registerLogSink(ComponentRustLogSink)
	uniffi.kapun_dcql_sdjwt_rust.registerLogSink(ComponentRustLogSink)
	uniffi.kapun_wallet_rust.registerLogSink(ComponentRustLogSink)
}
