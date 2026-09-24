/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.kapunsdk.wallet

import org.kapunsdk.util.log.LogSink
import org.kapunsdk.util.log.Logger
import org.kapunsdk.util.network.KapunNetworkConfiguration

actual class KapunSdk {
	actual fun initialize(logSink: LogSink?, databaseName: String) {
		initialize(logSink, databaseName, KapunNetworkConfiguration())
	}

	actual fun initialize(logSink: LogSink?, databaseName: String, networkConfiguration: KapunNetworkConfiguration) {
		Logger.sink = logSink
		bridgeAllRustLogSinks()
		logKapunSdkInitialized()
	}

	actual fun setUntrustedCertificatesAllowed(allow: Boolean) = Unit

}
