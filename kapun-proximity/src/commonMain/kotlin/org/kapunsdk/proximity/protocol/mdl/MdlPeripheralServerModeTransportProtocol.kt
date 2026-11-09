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
package org.kapunsdk.proximity.protocol.mdl

import org.kapunsdk.proximity.ProximityError
import org.kapunsdk.proximity.ble.BleGattFactory
import org.kapunsdk.proximity.ble.BleL2capConnection
import org.kapunsdk.proximity.ble.BleL2capListener
import org.kapunsdk.proximity.ble.BleL2capServer
import org.kapunsdk.proximity.ble.ProximityBleOptions
import org.kapunsdk.proximity.ble.client.BleGattClient
import org.kapunsdk.proximity.ble.client.BleGattClientListener
import org.kapunsdk.proximity.ble.client.BleScannerListener
import org.kapunsdk.proximity.ble.gatt.BleGattCharacteristic
import org.kapunsdk.proximity.ble.gatt.BleGattCharacteristicDescriptor
import org.kapunsdk.proximity.ble.gatt.BleGattService
import org.kapunsdk.proximity.ble.server.BleAdvertiserListener
import org.kapunsdk.proximity.ble.server.BleGattServer
import org.kapunsdk.proximity.ble.server.BleGattServerListener
import org.kapunsdk.proximity.ble.server.GattRequestResult
import org.kapunsdk.proximity.di.KapunProximityKoinComponent
import org.kapunsdk.proximity.protocol.BleTransportProtocol
import org.kapunsdk.util.extensions.asBytes
import org.kapunsdk.util.extensions.asLong
import org.kapunsdk.util.extensions.asOrderedObject
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.toCbor
import org.kapunsdk.util.log.Logger
import org.koin.core.component.inject
import uniffi.kapun_crypto_rust.EphemeralKey
import uniffi.kapun_crypto_rust.SessionCipher
import uniffi.kapun_util_rust.JsonNumber
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.decodeCbor
import uniffi.kapun_util_rust.encodeCbor
import kotlin.uuid.Uuid

internal class MdlPeripheralServerModeTransportProtocol(
	role: Role,
	private val serviceUuid: Uuid,
	private val ephemeralKey: EphemeralKey,
	private val deviceMacAddress: String? = null,
	private val options: ProximityBleOptions = ProximityBleOptions.Default,
	private val l2capPsm: Int? = null,
	private val enableL2cap: Boolean = true,
) : BleTransportProtocol(role), KapunProximityKoinComponent, MdlTransportProtocolExtensions {

	companion object {
		private const val TAG = "MdlPeripheralServerMode"

		// ISO-18013-5 Table 11
		val characteristicStateUuid = Uuid.parse("00000001-A123-48CE-896B-4C76973373E6")
		val characteristicClient2ServerUuid = Uuid.parse("00000002-A123-48CE-896B-4C76973373E6")
		val characteristicServer2ClientUuid = Uuid.parse("00000003-A123-48CE-896B-4C76973373E6")
		val characteristicConfigurationUuid = Uuid.parse("00002902-0000-1000-8000-00805f9b34fb")
	}

	private val gattFactory by inject<BleGattFactory>()
	private val characteristicsFactory by inject<MdlCharacteristicsFactory>()

	private var gattServer: BleGattServer? = null
	private var gattClient: BleGattClient? = null
	private var l2capServer: BleL2capServer? = null
	private var l2capClient: BleL2capConnection? = null
	private var preparedL2capPsm: Int? = null
	private var l2capServerHasAcceptedPeer = false
	private var l2capConnectionWasEstablished = false
	private var l2capFallbackToGatt = false
	private var l2capFallbackGattConnected = false
	private var l2capSidecarOnly = false
	private var l2capSessionCompleted = false
	override var sessionTranscript: Value? = null
	private val gattAdvertiserListener = object : BleAdvertiserListener {
		override fun onError(msg: String) {
			reportError(ProximityError.Unknown(msg))
		}
	}

	/** Opens the local listener early enough to include its assigned PSM in DeviceEngagement. */
	suspend fun prepareL2capServer(): Int? {
		if (role != Role.WALLET) {
			Logger(TAG).debug("Skipping L2CAP listener setup for role=$role")
			return null
		}
		if (l2capServer != null) {
			Logger(TAG).debug("L2CAP listener already prepared: psm=$preparedL2capPsm")
			return preparedL2capPsm
		}
		val server = gattFactory.createL2capServer() ?: run {
			Logger(TAG).debug("L2CAP server is unavailable on this platform; using GATT")
			return null
		}
		return try {
			val psm = server.listen()
			l2capServer = server
			preparedL2capPsm = psm
			Logger(TAG).debug("L2CAP listener ready: psm=$psm")
			psm
		} catch (e: Exception) {
			server.close()
			Logger(TAG).warn("Unable to open L2CAP listener: ${e.message}")
			null
		}
	}

	fun isSupported() : Boolean {
		if(this.role == Role.WALLET) {
			return gattFactory.isBleAdvSupported()
		}
		return true
	}

	override fun getSessionCipher(engagementBytes: ByteArray ,eReaderKeyBytes: ByteArray, peerCoseKey: ByteArray?) : SessionCipher? {
		sessionTranscript = listOf(24 to engagementBytes, 24 to eReaderKeyBytes, Value.Null).toCbor()
		val sessionTranscriptBs = encodeCbor(sessionTranscript!!)
		val sessionTranscriptBytes = encodeCbor(
			(24 to sessionTranscriptBs).toCbor()
		)
		val coseKey = runCatching { decodeCbor(peerCoseKey?: eReaderKeyBytes) }.getOrNull() ?: return null
		val kty = coseKey.asOrderedObject()?.get(Value.Number(JsonNumber.Integer(1)))!!.asLong() ?: return null
		val publicKey = when(kty) {
			// OKP, only x coordinate
			1L -> {
				coseKey.asOrderedObject()?.get(Value.Number(JsonNumber.Integer(-2)))!!.asBytes() ?: return null
			}
			// EC key sec1 bytes
			2L -> {
				val x = coseKey.asOrderedObject()?.get(Value.Number(JsonNumber.Integer(-2)))!!.asBytes() ?: return null
				val y = coseKey.asOrderedObject()?.get(Value.Number(JsonNumber.Integer(-3)))!!.asBytes() ?: return null
				byteArrayOf(0x04) + x + y
			}
			else -> return null
		}
		return this.ephemeralKey.getSessionCipher(sessionTranscriptBytes,publicKey)
	}

	override suspend fun connect() {
		restoreCallbacksForReconnect()
		l2capSidecarOnly = false
		l2capFallbackToGatt = false
		l2capFallbackGattConnected = false
		l2capSessionCompleted = false
		// In peripheral server mode, the wallet (or mDL) acts as the server (advertising) and the verifier (or mDL reader) acts as the client (scanning)
		when (role) {
			Role.WALLET -> connectAsServer()
			Role.VERIFIER -> connectAsClient()
		}
	}

	override fun disconnect() {
		Logger(TAG).debug(
			"Disconnecting BLE transport: role=$role l2capPsm=$preparedL2capPsm " +
				"l2capConnected=${l2capClient?.isConnected == true || l2capServer?.isConnected == true}"
		)
		reportDisconnected()
		inhibitCallbacks()

		runCatching { sendTransportSpecificTerminationMessage() }
		l2capServer?.close()
		l2capServer = null
		preparedL2capPsm = null
		l2capServerHasAcceptedPeer = false
		l2capConnectionWasEstablished = false
		l2capClient?.close()
		l2capClient = null

		gattServer?.apply {
			stopAdvertising()
			setListener(null)
			stop()
			gattServer = null
		}

		gattClient?.apply {
			stopScanning()
			setListener(null)
			disconnect()
			gattClient = null
		}
	}

	fun hasUsedL2cap(): Boolean = l2capConnectionWasEstablished && !l2capFallbackToGatt

	fun markSessionCompleted() {
		l2capSessionCompleted = true
	}

	fun hasPreparedL2capServer(): Boolean = l2capServer != null

	/** Starts only this mode's L2CAP leg while a different GATT mode is selected. */
	suspend fun connectL2capSidecar() {
		restoreCallbacksForReconnect()
		l2capSidecarOnly = true
		l2capConnectionWasEstablished = false
		l2capFallbackToGatt = false
		l2capFallbackGattConnected = false
		l2capServerHasAcceptedPeer = false
		l2capSessionCompleted = false
		when (role) {
			Role.WALLET -> connectAsServer()
			Role.VERIFIER -> connectAsL2capClientOnly()
		}
	}

	override fun sendMessage(data: ByteArray, onProgress: ((sent: Int, total: Int) -> Unit)?) {
		if (l2capClient?.isConnected == true || l2capServer?.isConnected == true) {
			val connection = l2capClient ?: l2capServer ?: error("No L2CAP connection available")
			connection.writeMessage(data)
			onProgress?.invoke(data.size, data.size)
			return
		}
		val charUuid = when (role) {
			Role.WALLET -> characteristicServer2ClientUuid
			Role.VERIFIER -> characteristicClient2ServerUuid
		}

		when {
			gattServer != null -> {
				gattServer?.writeCharacteristic(charUuid, data, onProgress)
			}
			gattClient != null -> gattClient?.writeCharacteristic(charUuid, data, onProgress)
			else -> throw IllegalStateException("No Gatt Server or Gatt Client available")
		}
	}

	override fun sendTransportSpecificTerminationMessage() {
		if (l2capConnectionWasEstablished && !l2capFallbackToGatt) {
			// CoC termination is signaled by closing the channel. ISO's GATT state-characteristic
			// termination byte is not an L2CAP message and must not be written into the CoC stream.
			Logger(TAG).debug("L2CAP CoC has no transport-specific termination frame; channel close will terminate the session")
			return
		}
		val terminationCode = byteArrayOf(0x02.toByte())

		when {
			gattServer != null -> gattServer?.writeCharacteristicNonChunked(characteristicStateUuid, terminationCode)
			gattClient != null -> gattClient?.writeCharacteristicNonChunked(characteristicStateUuid, terminationCode)
			else -> throw IllegalStateException("No Gatt Server or Gatt Client available")
		}
	}

	override fun supportsTransportSpecificTerminationMessage(): Boolean {
		if (l2capConnectionWasEstablished && !l2capFallbackToGatt) return false
		return when {
			gattServer != null -> gattServer?.supportsSessionTermination() ?: false
			gattClient != null -> gattClient?.supportsSessionTermination() ?: false
			else -> false
		}
	}

	private fun connectAsServer() {
		l2capServerHasAcceptedPeer = false
		if (l2capServer != null) {
			Logger(TAG).debug("Waiting for L2CAP peer on psm=$preparedL2capPsm")
			l2capServer?.accept(l2capListener)
		} else {
			Logger(TAG).debug("No L2CAP listener prepared; wallet will use GATT")
		}
		gattServer = gattFactory.createServer(serviceUuid).apply {
			setListener(serverListener)
			val characteristics = characteristicsFactory.createServerWalletCharacteristics()

			if (!start(characteristics)) {
				reportError(ProximityError.Unknown("Error starting Gatt Server"))
				stop()
				gattServer = null
				l2capServer?.close()
				l2capServer = null
				preparedL2capPsm = null
				return
			}

			startAdvertising(gattAdvertiserListener)
		}
	}

	private fun connectAsClient() {
		if (l2capPsm != null && enableL2cap) {
			Logger(TAG).debug("Engagement includes L2CAP PSM=$l2capPsm; trying L2CAP before GATT")
			val client = gattFactory.createL2capClient()
			if (client != null) {
				l2capClient = client
				try {
					client.connect(serviceUuid, l2capPsm, deviceMacAddress, l2capListener)
					return
				} catch (e: Exception) {
					Logger(TAG).warn("Unable to start L2CAP connection, falling back to GATT: ${e.message}")
					client.close()
					l2capClient = null
				}
			}
		} else if (l2capPsm == null) {
			Logger(TAG).debug("No L2CAP PSM configured for this peripheral GATT transport; continuing with GATT")
		} else {
			Logger(TAG).debug("L2CAP disabled by caller; using GATT despite engagement PSM")
		}
		Logger(TAG).debug("Starting GATT client transport")
		connectAsGattClient()
	}

	private fun connectAsL2capClientOnly() {
		if (l2capPsm == null || !enableL2cap) {
			Logger(TAG).debug("L2CAP sidecar unavailable; selected GATT mode remains active")
			reportError(ProximityError.Unknown("L2CAP PSM is unavailable"))
			return
		}
		val client = gattFactory.createL2capClient() ?: run {
			Logger(TAG).debug("L2CAP client unavailable; selected GATT mode remains active")
			reportError(ProximityError.Unknown("L2CAP client is unavailable"))
			return
		}
		l2capClient = client
		try {
			Logger(TAG).debug("Starting peripheral-mode L2CAP sidecar: psm=$l2capPsm")
			client.connect(serviceUuid, l2capPsm, deviceMacAddress, l2capListener)
		} catch (e: Exception) {
			Logger(TAG).warn("Unable to start L2CAP sidecar; selected GATT mode remains active: ${e.message}")
			client.close()
			l2capClient = null
			reportError(ProximityError.Unknown(e.message ?: "Unable to start L2CAP client"))
		}
	}

	private fun connectAsGattClient() {
		gattClient = gattFactory.createClient(serviceUuid, options).apply {
			setListener(clientListener)

			if (!deviceMacAddress.isNullOrEmpty()) {
				connect(deviceMacAddress)
			} else {
				startScanning(
					object : BleScannerListener {
						override fun onError(msg: String) {
							reportError(ProximityError.Unknown(msg))
						}
					}
				)
			}
		}
	}

	private val l2capListener = object : BleL2capListener {
		override fun onConnected() {
			if (role == Role.WALLET) l2capServerHasAcceptedPeer = true
			l2capConnectionWasEstablished = true
			Logger(TAG).debug("L2CAP transport connected: role=$role")
			reportConnected()
			gattServer?.stopAdvertising()
		}

		override fun onMessageReceived(data: ByteArray) {
			Logger(TAG).debug("L2CAP transport received message: bytes=${data.size}")
			reportMessageReceived(data)
		}

		override fun onDisconnected() {
			if (!l2capSidecarOnly && l2capFallbackToGatt && !l2capConnectionWasEstablished) {
				Logger(TAG).debug("Ignoring L2CAP cleanup disconnect after GATT fallback started")
				return
			}
			if (role == Role.WALLET && l2capServer != null && !l2capServerHasAcceptedPeer) {
				Logger(TAG).debug("L2CAP listener ended before accepting a peer; GATT remains available")
				return
			}
			if (!l2capSidecarOnly && l2capConnectionWasEstablished && l2capSessionCompleted) {
				Logger(TAG).debug("L2CAP disconnected after successful session completion; not starting GATT fallback")
				reportDisconnected()
				return
			}
			if (!l2capSidecarOnly && !l2capConnectionWasEstablished && l2capPsm != null && !l2capFallbackToGatt) {
				l2capFallbackToGatt = true
				l2capClient?.close()
				l2capClient = null
				Logger(TAG).warn("L2CAP disconnected before connecting; falling back to GATT: role=$role")
				connectAsGattClient()
				return
			}
			if (!l2capSidecarOnly && l2capConnectionWasEstablished) {
				l2capFallbackToGatt = true
				l2capFallbackGattConnected = false
				l2capServerHasAcceptedPeer = false
				Logger(TAG).warn("L2CAP channel disconnected; keeping the session and falling back to GATT: role=$role")
				if (role == Role.WALLET) {
					gattServer?.startAdvertising(gattAdvertiserListener)
				} else {
					connectAsGattClient()
				}
				return
			}
			Logger(TAG).debug("L2CAP transport disconnected: role=$role")
			reportDisconnected()
		}

		override fun onError(message: String) {
			if (!l2capSidecarOnly && l2capFallbackToGatt && !l2capConnectionWasEstablished) {
				Logger(TAG).debug("Ignoring late L2CAP error after GATT fallback started: $message")
				return
			}
			val client = l2capClient
			if (client != null && !isConnected) {
				Logger(TAG).warn(
					if (l2capSidecarOnly) "L2CAP sidecar failed; selected GATT mode remains active: $message"
					else "L2CAP connection failed, falling back to GATT: $message"
				)
				client.close()
				l2capClient = null
				if (!l2capSidecarOnly) {
					l2capFallbackToGatt = true
					l2capFallbackGattConnected = false
					connectAsGattClient()
				}
				else reportError(ProximityError.Unknown(message))
			} else if (!l2capSidecarOnly && l2capConnectionWasEstablished) {
				Logger(TAG).warn("L2CAP channel error after connection; waiting for disconnect callback to switch to GATT: $message")
			} else if (role == Role.WALLET && l2capServerHasAcceptedPeer) {
				// The sidecar wrapper handles the matching disconnect by switching the existing session to GATT.
				Logger(TAG).warn("L2CAP sidecar failed after accepting a peer; awaiting disconnect cleanup: $message")
			} else if (l2capServer != null && !l2capServer!!.isConnected) {
				Logger(TAG).warn("L2CAP accept failed; GATT advertising remains available: $message")
				if (l2capSidecarOnly) reportError(ProximityError.Unknown(message))
			} else {
				Logger(TAG).warn("L2CAP transport failed: $message")
				reportError(ProximityError.Unknown(message))
			}
		}
	}

	private val serverListener = object : BleGattServerListener {
		override fun onPeerConnecting() {
			if (!l2capSidecarOnly) reportConnecting()
		}

		override fun onPeerConnected() {
//			reportConnected()
			gattServer?.stopAdvertising()
		}

		override fun onPeerDisconnected() {
			if (l2capServerHasAcceptedPeer) {
				Logger(TAG).debug("Ignoring GATT disconnect after L2CAP accepted the peer; L2CAP owns session lifecycle")
				return
			}
			if (l2capFallbackToGatt && !l2capFallbackGattConnected) {
				Logger(TAG).debug("Ignoring GATT disconnect before L2CAP-to-GATT fallback completed; keeping advertising available")
				gattServer?.startAdvertising(gattAdvertiserListener)
				return
			}
			if (l2capServer != null && !l2capServerHasAcceptedPeer && !isConnected) {
				Logger(TAG).debug("GATT peer left before session handshake; preserving engagement and restarting advertising")
				gattServer?.startAdvertising(gattAdvertiserListener)
				return
			}
			if (!l2capSidecarOnly) reportDisconnected()
		}

		override fun onError(error: ProximityError) {
			if (!l2capSidecarOnly) reportError(error)
		}

		override fun onCharacteristicWriteRequest(characteristic: BleGattCharacteristic): GattRequestResult {
			if (l2capSidecarOnly) return GattRequestResult(isSuccessful = true)
			if (characteristic.uuid == characteristicStateUuid) {
				val value = characteristic.value
				return when {
					value == null -> {
						reportError(ProximityError.Unknown("Value is null"))
						GattRequestResult(isSuccessful = false)
					}
					value.size != 1 -> {
						reportError(ProximityError.Unknown("Value has invalid size (${value.size})"))
						GattRequestResult(isSuccessful = false)
					}
					value[0] == 0x02.toByte() -> {
						reportTransportSpecificSessionTermination()
						GattRequestResult(isSuccessful = true)
					}
					value[0] == 0x01.toByte() -> {
						if (l2capFallbackToGatt) l2capFallbackGattConnected = true
						reportConnected()
						GattRequestResult(isSuccessful = true)
					}
					else -> {
						reportError(ProximityError.Unknown("Invalid value for state characteristic"))
						GattRequestResult(isSuccessful = false)
					}
				}
			} else {
				characteristic.value?.let { reportMessageReceived(it) }
				return GattRequestResult(isSuccessful = true)
			}
		}

	}

	private val clientListener = object : BleGattClientListener {
		override fun onPeerConnecting() {
			if (!l2capSidecarOnly) reportConnecting()
		}

		override fun onPeerConnected() {
			if (l2capSidecarOnly) return
			if (l2capFallbackToGatt) l2capFallbackGattConnected = true
			reportConnected()
			gattClient?.writeCharacteristicNonChunked(characteristicStateUuid, byteArrayOf(0x01));
		}

		override fun onPeerDisconnected() {
			if (l2capSidecarOnly) return
			gattClient?.apply {
				setListener(null)
				disconnect()
				gattClient = null
			}
			reportDisconnected()
		}

		override fun onMtuChanged(mtu: Int) {
			// TODO Read Ident characteristic
			Logger(TAG).debug("MTU changed: mtu=$mtu")
		}

		override fun onError(error: ProximityError) {
			if (!l2capSidecarOnly) reportError(error)
		}

		override fun onServicesDiscovered(services: List<BleGattService>): List<BleGattCharacteristic> {
			if (l2capSidecarOnly) return emptyList()
			val service = services.singleOrNull { it.uuid == serviceUuid }
			if (service != null) {
				val stateCharacteristic = service.characteristics.singleOrNull { it.uuid == characteristicStateUuid }
				if (stateCharacteristic == null) {
					reportError(ProximityError.Unknown("State characteristic not found"))
					return emptyList()
				}

				val client2ServerCharacteristic =
					service.characteristics.singleOrNull { it.uuid == characteristicClient2ServerUuid }
				if (client2ServerCharacteristic == null) {
					reportError(ProximityError.Unknown("Client2Server characteristic not found"))
					return emptyList()
				}

				val server2ClientCharacteristic =
					service.characteristics.singleOrNull { it.uuid == characteristicServer2ClientUuid }
				if (server2ClientCharacteristic == null) {
					reportError(ProximityError.Unknown("Server2Client characteristic not found"))
					return emptyList()
				}

				return listOf(
					stateCharacteristic,
					client2ServerCharacteristic,
					server2ClientCharacteristic,
				)
			} else {
				reportError(ProximityError.Unknown("Service not found"))
				return emptyList()
			}
		}

		override fun onCharacteristicRead(characteristic: BleGattCharacteristic) {
			if (l2capSidecarOnly) return
			// TODO Protocol specific stuff (handle Ident)
			characteristic.value?.let { reportMessageReceived(it) }
		}

		override fun onCharacteristicWrite(characteristic: BleGattCharacteristic) {
			if (l2capSidecarOnly) return
			if (characteristic.uuid == characteristicStateUuid) {
				reportConnected()
			}
		}

		override fun onCharacteristicChanged(characteristic: BleGattCharacteristic) {
			if (l2capSidecarOnly) return
			if (characteristic.uuid == characteristicStateUuid) {
				val value = characteristic.value
				when {
					value == null -> reportError(ProximityError.Unknown("Value is null"))
					value.size != 1 -> reportError(ProximityError.Unknown("Value has invalid size (${value.size})"))
					value[0] == 0x02.toByte() -> reportTransportSpecificSessionTermination()
					else -> reportError(ProximityError.Unknown("Invalid value for state characteristic"))
				}
			} else {
				characteristic.value?.let { reportMessageReceived(it) }
			}
		}

		override fun onDescriptorWrite(descriptor: BleGattCharacteristicDescriptor) {

		}
	}
}
