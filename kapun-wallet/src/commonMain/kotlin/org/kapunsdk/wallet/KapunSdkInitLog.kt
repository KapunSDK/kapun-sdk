package org.kapunsdk.wallet

import org.kapunsdk.util.log.Logger
import uniffi.kapun_util_rust.logBridgeConfirmation

/**
 * Logs SDK initialization along with [KapunSdkInfo], so a registered [org.kapunsdk.util.log.LogSink]
 * always has a record of exactly which SDK build (version + git commit) is running - useful when
 * comparing what a host app logs/displays against what was actually built. Called once from each
 * platform's `KapunSdk.initialize()`, after the log sink has been assigned.
 *
 * Also fires one deterministic Rust-originated log line ([logBridgeConfirmation]) so a host app
 * can confirm Rust logs reach its sink too, without needing to trigger a specific credential flow.
 */
internal fun logKapunSdkInitialized() {
	Logger("KapunSdk").info(
		"KapunSdk initialized (version=${KapunSdkInfo.VERSION}, commit=${KapunSdkInfo.GIT_COMMIT})",
	)
	logBridgeConfirmation()
}
