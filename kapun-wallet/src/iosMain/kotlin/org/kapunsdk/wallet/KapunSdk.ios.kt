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

import org.kapunsdk.issuance.KapunIssuance
import org.kapunsdk.trust.KapunTrust
import org.kapunsdk.util.log.LogSink
import org.kapunsdk.util.log.Logger
import org.kapunsdk.util.network.KapunNetworkConfiguration
import org.kapunsdk.visualization.KapunVisualization
import org.kapunsdk.wallet.crypto.factories.HardwareSignerFactory
import org.kapunsdk.wallet.di.KapunWalletKoinContext
import org.koin.dsl.module

actual class KapunSdk(
	private val hardwareSignerFactory: HardwareSignerFactory,
) {

	actual fun initialize(
		logSink: LogSink?,
		databaseName: String,
		networkConfiguration: KapunNetworkConfiguration,
	) {
		Logger.sink = logSink
		bridgeAllRustLogSinks()
		uniffi.kapun_wallet_rust.setUntrustedTls(networkConfiguration.allowUntrustedCertificates)
		KapunTrust().initialize(networkConfiguration)
		KapunIssuance().initialize(networkConfiguration)
		KapunVisualization().initialize()
		KapunWalletKoinContext.initialize(databaseName, networkConfiguration) {
			modules(
				module {
					single<HardwareSignerFactory> { hardwareSignerFactory }
				},
			)
		}
		logKapunSdkInitialized()
	}

	actual fun setUntrustedCertificatesAllowed(allow: Boolean) {
		uniffi.kapun_wallet_rust.setUntrustedTls(allow)
		uniffi.kapun_trust_rust.setUntrustedTls(allow)
		uniffi.kapun_util_rust.setUntrustedTls(allow)
	}

}
