package org.kapunsdk.wallet

import org.kapunsdk.util.log.LogSink
import org.kapunsdk.util.network.KapunNetworkConfiguration

const val DEFAULT_DATABASE_NAME = "kapun_database.sqlite"

expect class KapunSdk {

	/**
	 * @param logSink Receives this SDK's log output; see [org.kapunsdk.util.log.Logger]. When
	 * null (the default), the SDK logs nothing.
	 */
	fun initialize(
		logSink: LogSink? = null,
		databaseName: String = DEFAULT_DATABASE_NAME,
	)

	fun initialize(
		logSink: LogSink? = null,
		databaseName: String = DEFAULT_DATABASE_NAME,
		networkConfiguration: KapunNetworkConfiguration,
	)

	/** Updates the TLS policy for SDK-owned Rust requests at runtime. */
	fun setUntrustedCertificatesAllowed(allow: Boolean)

}

/**
 * The running SDK build as `<version> (<git commit>)`, e.g. `"1.0.0 (c825de8)"` - for a host app to
 * display in a debug/settings screen.
 */
fun KapunSdk.version(): String = "${KapunSdkInfo.VERSION} (${KapunSdkInfo.GIT_COMMIT})"
