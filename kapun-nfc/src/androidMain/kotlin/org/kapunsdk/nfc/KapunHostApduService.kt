/* Copyright 2026 Ubique Innovation AG

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
package org.kapunsdk.nfc

import android.nfc.cardemulation.HostApduService
import android.os.Bundle

/**
 * Base class for host card emulation services. Subclasses provide the emulated applications via [createHandlers]
 * and must be declared in the app manifest together with a `host-apdu-service` resource listing their AIDs.
 *
 * Commands are processed synchronously on the main thread, so handlers must respond quickly.
 */
abstract class KapunHostApduService : HostApduService() {

	private val dispatcher by lazy { ApduDispatcher(createHandlers()) }

	protected abstract fun createHandlers(): List<ApduHandler>

	override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
		return dispatcher.process(commandApdu)
	}

	override fun onDeactivated(reason: Int) {
		dispatcher.reset(
			when (reason) {
				DEACTIVATION_DESELECTED -> DeselectReason.DESELECTED
				else -> DeselectReason.LINK_LOSS
			}
		)
	}
}
