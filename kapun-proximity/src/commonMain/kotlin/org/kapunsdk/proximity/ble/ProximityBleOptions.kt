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
package org.kapunsdk.proximity.ble

/**
 * Tuning options for the BLE transport, applied by the side acting as GATT client (central).
 *
 * Every option defaults to the behaviour the SDK had before they existed, so a caller that does not
 * set them gets an unchanged code path. They exist to be toggled one at a time and measured against
 * that baseline on the same device pair.
 */
public data class ProximityBleOptions(
	/**
	 * Negotiate the ATT MTU before discovering services rather than after.
	 *
	 * Service discovery otherwise runs at the default ATT MTU of 23 bytes, where a Read By Type
	 * Response carries a single 128-bit-UUID entry per PDU. Measured discovery cost scales with the
	 * peer's service count at roughly 191 ms per service, which this is meant to reduce.
	 */
	public val mtuBeforeDiscovery: Boolean = false,

	/**
	 * Ask for the LE 2M PHY on connect and again once connected.
	 *
	 * The peer may refuse, in which case the link stays on 1M. The negotiated PHY is logged either
	 * way, which is the part that is currently unobservable.
	 */
	public val preferLe2MPhy: Boolean = false,
) {
	public companion object {
		/** The pre-existing behaviour: MTU after discovery, no PHY preference. */
		public val Default: ProximityBleOptions = ProximityBleOptions()
	}
}
