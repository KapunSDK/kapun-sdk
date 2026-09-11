/* Copyright 2024 Ubique Innovation AG

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

import android.bluetooth.BluetoothManager
import android.content.Context
import org.kapunsdk.proximity.ble.client.BleGattClient
import org.kapunsdk.proximity.ble.client.GattClient
import org.kapunsdk.proximity.ble.server.BleGattServer
import org.kapunsdk.proximity.ble.server.GattServer
import org.kapunsdk.util.log.Logger
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

internal actual class BleGattFactory(private val context: Context) {
	companion object {
		private const val TAG = "BleGattFactory"
	}

	internal actual fun isBleAdvSupported() : Boolean {
		val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
		val adapter = bm.adapter ?: return false
		// Connectable advertising is what central client mode needs. isLePeriodicAdvertisingSupported
		// answers a different question (BT 5.0 periodic advertising) and is false on devices that
		// advertise perfectly well, which silently disabled central client mode for the verifier.
		val supported = adapter.isEnabled && adapter.bluetoothLeAdvertiser != null
		Logger(TAG).debug(
			"ble advertising supported=$supported (multiAdvertisement=${adapter.isMultipleAdvertisementSupported}, periodic=${adapter.isLePeriodicAdvertisingSupported})"
		)
		return supported
	}
	internal actual fun createServer(
		serviceUuid: Uuid,
	): BleGattServer {
		val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
		return GattServer(
			context = context,
			bluetoothManager = bm,
			serviceUuid = serviceUuid.toJavaUuid(),
			encodedEphemeralDeviceKey = null, // TODO CBOR encoded ephemeral device public key
		)
	}

	internal actual fun createClient(
		serviceUuid: Uuid,
		options: ProximityBleOptions,
	): BleGattClient {
		val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
		return GattClient(
			context = context,
			bluetoothManager = bm,
			serviceUuid = serviceUuid.toJavaUuid(),
			encodedEphemeralDeviceKey = null, // TODO CBOR encoded ephemeral device public key
			options = options,
		)
	}

}
