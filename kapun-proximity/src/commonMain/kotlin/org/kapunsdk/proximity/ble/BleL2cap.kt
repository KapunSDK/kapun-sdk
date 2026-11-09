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

import kotlin.uuid.Uuid

/** Platform-neutral stream socket used by the ISO BLE L2CAP transport. */
internal interface BleL2capConnection {
    val isConnected: Boolean

    fun writeMessage(data: ByteArray)

    fun close()
}

internal interface BleL2capListener {
    fun onConnected()

    fun onMessageReceived(data: ByteArray)

    fun onDisconnected()

    fun onError(message: String)
}

internal interface BleL2capServer : BleL2capConnection {
    /** Opens the listener and returns the dynamically assigned PSM for DeviceEngagement. */
    suspend fun listen(): Int

    fun accept(listener: BleL2capListener)
}

internal interface BleL2capClient : BleL2capConnection {
    /** Scans for the existing advertised BLE service UUID, then opens CoC without GATT. */
    fun connect(
        serviceUuid: Uuid,
        psm: Int,
        deviceMacAddress: String?,
        listener: BleL2capListener,
    )
}
