package org.kapunsdk.wallet

import org.kapunsdk.util.log.LogSink

expect class KapunSdk {

	/**
	 * @param logSink Receives this SDK's log output; see [org.kapunsdk.util.log.Logger]. When
	 * null (the default), the SDK logs nothing.
	 */
	fun initialize(logSink: LogSink? = null)

}
