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

package org.kapunsdk.wallet.process.refresh.eaa

import org.kapunsdk.trust.TrustFrameworkController
import org.kapunsdk.wallet.credentials.activity.ActivityRepository
import org.kapunsdk.wallet.credentials.credential.CredentialsRepository
import org.kapunsdk.wallet.credentials.identity.IdentityRepository
import org.kapunsdk.wallet.credentials.oca.OcaRepository
import org.kapunsdk.wallet.credentials.oca.networking.OcaServiceController
import org.kapunsdk.wallet.crypto.SecureHardwareAccess
import org.kapunsdk.wallet.crypto.SigningProvider
import org.kapunsdk.wallet.keyvalue.KeyValueRepository
import org.kapunsdk.wallet.process.ProcessEvent
import org.kapunsdk.wallet.process.ProcessHandler
import org.kapunsdk.wallet.process.ProcessStep
import uniffi.kapun_wallet_rust.WalletBackend

class EaaRefreshProcessHandler(
	private val walletBackend: WalletBackend,
	private val trustController: TrustFrameworkController,
	private val credentialsRepository: CredentialsRepository,
	private val identityRepository: IdentityRepository,
	private val secureHardwareAccess: SecureHardwareAccess,
	private val signingProvider: SigningProvider,
	private val ocaRepository: OcaRepository,
	private val ocaServiceController: OcaServiceController,
	private val activityRepository: ActivityRepository,
	private val keyValueRepository: KeyValueRepository
): ProcessHandler {

	private var currentProcess: EaaRefreshProcess? = null

	override suspend fun handleProcessStep(
		current: ProcessStep?,
		inputEvent: ProcessEvent,
	): ProcessStep? {
		return when {
			inputEvent is EaaRefreshProcessEvent.RefreshRequests -> {
				currentProcess = EaaRefreshProcess(
					walletBackend,
					trustController,
					credentialsRepository,
					identityRepository,
					secureHardwareAccess,
					signingProvider,
					ocaRepository,
					ocaServiceController,
					activityRepository,
					keyValueRepository,
				)
				currentProcess?.startEaaRefresh(inputEvent.identity)
			}
			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}
}
