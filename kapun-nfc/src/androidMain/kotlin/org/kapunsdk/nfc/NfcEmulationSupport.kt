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

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.nfc.cardemulation.HostApduService

object NfcEmulationSupport {

	fun isHceSupported(context: Context): Boolean {
		return context.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)
	}

	fun isNfcEnabled(context: Context): Boolean {
		return NfcAdapter.getDefaultAdapter(context)?.isEnabled == true
	}

	fun isDefaultServiceForAid(context: Context, service: Class<out HostApduService>, aid: String): Boolean {
		val cardEmulation = cardEmulation(context) ?: return false
		return cardEmulation.isDefaultServiceForAid(ComponentName(context, service), aid)
	}

	/**
	 * Prefers [service] over other services registered for the same AIDs while [activity] is in the foreground.
	 * Call from `onResume` and pair with [unsetPreferredService] in `onPause`.
	 */
	fun setPreferredService(activity: Activity, service: Class<out HostApduService>): Boolean {
		val cardEmulation = cardEmulation(activity) ?: return false
		return cardEmulation.setPreferredService(activity, ComponentName(activity, service))
	}

	fun unsetPreferredService(activity: Activity): Boolean {
		val cardEmulation = cardEmulation(activity) ?: return false
		return cardEmulation.unsetPreferredService(activity)
	}

	private fun cardEmulation(context: Context): CardEmulation? {
		val adapter = NfcAdapter.getDefaultAdapter(context) ?: return null
		return CardEmulation.getInstance(adapter)
	}
}
