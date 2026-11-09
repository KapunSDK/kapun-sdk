/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

package org.kapunsdk.proximity.protocol.mdl

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.kapunsdk.proximity.ProximityError
import org.kapunsdk.proximity.ble.ProximityBleOptions
import org.kapunsdk.proximity.di.KapunProximityKoinComponent
import org.kapunsdk.proximity.protocol.BleTransportProtocol
import org.kapunsdk.proximity.protocol.TransportProtocol
import org.kapunsdk.util.log.Logger
import uniffi.kapun_crypto_rust.EphemeralKey
import uniffi.kapun_crypto_rust.SessionCipher
import uniffi.kapun_util_rust.Value
import kotlin.uuid.Uuid

internal class MdlTransportProtocol(
	role: Role,
	private val serviceUuidCentralMode: Uuid?,
	private val serviceUuidPeripheralMode: Uuid?,
	private val ephemeralKey: EphemeralKey,
	private val deviceMacAddress: String? = null,
	private val options: ProximityBleOptions = ProximityBleOptions.Default,
	private val l2capPsm: Int? = null,
	private val enableL2cap: Boolean = true,
	private val isEngagementPresenter: Boolean = false,
) : BleTransportProtocol(role), KapunProximityKoinComponent, MdlTransportProtocolExtensions {
	var centralClientModeTransportProtocol: MdlCentralClientModeTransportProtocol? = null
		private set
	var peripheralServerModeTransportProtocol: MdlPeripheralServerModeTransportProtocol? = null
		private set

	private var centralClientModeSelected = false
	private var l2capSidecarEnabled = false
	private var activeSidecarTransport: SidecarTransport? = null
	private var sharedSessionTranscript: Value? = null
	private var upstreamListener: TransportProtocol.Listener? = null
	private var suppressSidecarCallbacks = false
	private var selectedGattStarted = false
	private var l2capFallbackTriggered = false
	private var sessionCompleted = false
	private var upstreamSidecarConnected = false
	private var deferredGattError: ProximityError? = null
	private var l2capFallbackJob: Job? = null
	private var selectedGattFallbackJob: Job? = null
	private var fallbackScope = newFallbackScope()

	private enum class SidecarTransport { L2CAP, GATT }

	override var sessionTranscript: Value?
		get() = sharedSessionTranscript ?: when (activeSidecarTransport) {
			SidecarTransport.L2CAP -> (l2capProtocol() as? MdlTransportProtocolExtensions)?.sessionTranscript
			SidecarTransport.GATT -> (selectedGattProtocol() as? MdlTransportProtocolExtensions)?.sessionTranscript
			null -> if (centralClientModeTransportProtocol?.isConnected == true) {
				centralClientModeTransportProtocol?.sessionTranscript
			} else {
				peripheralServerModeTransportProtocol?.sessionTranscript
			}
		}
		set(value) {
			sharedSessionTranscript = value
		}

	init {
		centralClientModeTransportProtocol = serviceUuidCentralMode?.let {
			MdlCentralClientModeTransportProtocol(role, it, ephemeralKey, deviceMacAddress, options, l2capPsm, enableL2cap)
		}
		peripheralServerModeTransportProtocol = serviceUuidPeripheralMode?.let {
			MdlPeripheralServerModeTransportProtocol(role, it, ephemeralKey, deviceMacAddress, options, l2capPsm, enableL2cap)
		}
		if (centralClientModeTransportProtocol?.isSupported() == false) {
			Logger(TAG).warn("central client mode offered but not supported on this device, dropping it")
			centralClientModeTransportProtocol = null
		}
		if (peripheralServerModeTransportProtocol?.isSupported() == false) {
			Logger(TAG).warn("peripheral server mode offered but not supported on this device, dropping it")
			peripheralServerModeTransportProtocol = null
		}

		// If both GATT modes are offered, peripheral-server remains the synchronized
		// selection. Keep both protocol objects so the QR presenter/scanner can use the
		// L2CAP mode associated with the engagement direction independently of GATT.
		centralClientModeSelected = peripheralServerModeTransportProtocol == null && centralClientModeTransportProtocol != null
		val selected = when {
			centralClientModeSelected -> "centralClient"
			peripheralServerModeTransportProtocol != null -> "peripheralServer"
			else -> "none"
		}
		Logger(TAG).debug("transport mode selected: role=$role mode=$selected")
		if (selected == "none") {
			Logger(TAG).error("no usable BLE transport mode for role=$role, the session cannot connect")
		}
	}

	companion object {
		private const val TAG = "MdlTransportProtocol"
		private const val L2CAP_FALLBACK_DELAY_MS = 5_000L
	}

	private fun newFallbackScope() = CoroutineScope(SupervisorJob() + Dispatchers.Default)

	override fun getMessage(): ByteArray? {
		when (activeSidecarTransport) {
			SidecarTransport.L2CAP -> return l2capProtocol()?.getMessage()
			SidecarTransport.GATT -> return selectedGattProtocol()?.getMessage()
			null -> Unit
		}
		return when {
			!l2capFallbackTriggered && l2capSidecarEnabled && l2capProtocol()?.isConnected == true -> l2capProtocol()?.getMessage()
			selectedGattProtocol()?.isConnected == true -> selectedGattProtocol()?.getMessage()
			else -> null
		}
	}

	override fun setListener(listener: Listener) {
		super.setListener(listener)
		upstreamListener = listener
		configureListeners()
	}

	private fun configureListeners() {
		val listener = upstreamListener ?: return
		val selected = selectedGattProtocol()
		val l2cap = l2capProtocol()
		if (l2capSidecarEnabled && selected != null && l2cap != null && selected !== l2cap) {
			centralClientModeTransportProtocol?.let { protocol ->
				if (protocol === l2cap) protocol.setListener(sidecarListener(SidecarTransport.L2CAP))
				else if (protocol === selected) protocol.setListener(sidecarListener(SidecarTransport.GATT))
			}
			peripheralServerModeTransportProtocol?.let { protocol ->
				if (protocol === l2cap) protocol.setListener(sidecarListener(SidecarTransport.L2CAP))
				else if (protocol === selected) protocol.setListener(sidecarListener(SidecarTransport.GATT))
			}
		} else {
			selected?.setListener(listener)
		}
	}

	override suspend fun connect() {
		if (fallbackScope.coroutineContext[Job]?.isActive != true) {
			fallbackScope = newFallbackScope()
		}
		suppressSidecarCallbacks = false
		val selected = selectedGattProtocol()
		val l2cap = l2capProtocol()
		val l2capAvailable = if (isEngagementPresenter) {
			when (l2cap) {
				is MdlCentralClientModeTransportProtocol -> l2cap.hasPreparedL2capServer()
				is MdlPeripheralServerModeTransportProtocol -> l2cap.hasPreparedL2capServer()
				else -> false
			}
		} else {
			l2capPsm != null
		}
		l2capSidecarEnabled = enableL2cap && l2capAvailable && l2cap != null && selected != null && l2cap !== selected
		activeSidecarTransport = null
		selectedGattStarted = false
		l2capFallbackTriggered = false
		sessionCompleted = false
		upstreamSidecarConnected = false
		deferredGattError = null
		l2capFallbackJob?.cancel()
		selectedGattFallbackJob?.cancel()
		configureListeners()

		if (l2capSidecarEnabled) {
			Logger(TAG).debug("Starting selected GATT mode with ${if (isEngagementPresenter) "server" else "client"} L2CAP sidecar: role=$role")
			when (l2cap) {
				is MdlCentralClientModeTransportProtocol -> l2cap.connectL2capSidecar()
				is MdlPeripheralServerModeTransportProtocol -> l2cap.connectL2capSidecar()
			}
			Logger(TAG).debug("Keeping selected GATT mode idle for ${L2CAP_FALLBACK_DELAY_MS}ms while L2CAP connects")
			l2capFallbackJob = fallbackScope.launch {
				delay(L2CAP_FALLBACK_DELAY_MS)
				startSelectedGattFallback()
			}
		} else {
			selectedGattStarted = true
			selected?.connect()
		}
	}

	/** Open the local CoC listener before encoding this device's QR engagement. */
	suspend fun prepareL2capPsm(): Int? = when {
		!enableL2cap -> {
			Logger(TAG).debug("L2CAP disabled by caller")
			null
		}
		!isEngagementPresenter -> {
			Logger(TAG).debug("This device scans DeviceEngagement; it does not publish an L2CAP PSM")
			null
		}
		role == Role.WALLET -> peripheralServerModeTransportProtocol?.prepareL2capServer()
		role == Role.VERIFIER -> centralClientModeTransportProtocol?.prepareL2capServer()
		else -> null
	}

	fun hasUsedL2cap(): Boolean = when (activeSidecarTransport) {
		SidecarTransport.L2CAP -> true
		SidecarTransport.GATT -> false
		null -> !l2capFallbackTriggered && l2capHasUsed()
	}

	/** Prevent a peer's normal close after receiving the VP from being treated as L2CAP failure. */
	fun markSessionCompleted() {
		sessionCompleted = true
		when (val protocol = l2capProtocol()) {
			is MdlCentralClientModeTransportProtocol -> protocol.markSessionCompleted()
			is MdlPeripheralServerModeTransportProtocol -> protocol.markSessionCompleted()
		}
	}

	override fun disconnect() {
		suppressSidecarCallbacks = true
		l2capFallbackJob?.cancel()
		l2capFallbackJob = null
		selectedGattFallbackJob?.cancel()
		selectedGattFallbackJob = null
		fallbackScope.cancel()
		fallbackScope = newFallbackScope()
		centralClientModeTransportProtocol?.disconnect()
		peripheralServerModeTransportProtocol?.disconnect()
		activeSidecarTransport = null
	}

	override fun sendMessage(data: ByteArray, onProgress: ((sent: Int, total: Int) -> Unit)?) {
		when (activeSidecarTransport) {
			SidecarTransport.L2CAP -> l2capProtocol()?.sendMessage(data, onProgress)
			SidecarTransport.GATT -> selectedGattProtocol()?.sendMessage(data, onProgress)
			null -> if (!l2capFallbackTriggered && l2capSidecarEnabled && l2capHasUsed()) {
				l2capProtocol()?.sendMessage(data, onProgress)
			} else selectedGattProtocol()?.sendMessage(data, onProgress)
		}
	}

	override fun sendTransportSpecificTerminationMessage() {
		when (activeSidecarTransport) {
			SidecarTransport.L2CAP -> l2capProtocol()?.sendTransportSpecificTerminationMessage()
			SidecarTransport.GATT -> selectedGattProtocol()?.sendTransportSpecificTerminationMessage()
			null -> selectedGattProtocol()?.sendTransportSpecificTerminationMessage()
		}
	}

	override fun supportsTransportSpecificTerminationMessage(): Boolean = when (activeSidecarTransport) {
		SidecarTransport.L2CAP -> l2capProtocol()?.supportsTransportSpecificTerminationMessage() == true
		SidecarTransport.GATT -> selectedGattProtocol()?.supportsTransportSpecificTerminationMessage() == true
		null -> selectedGattProtocol()?.supportsTransportSpecificTerminationMessage() == true
	}

	override fun getSessionCipher(
		engagementBytes: ByteArray,
		eReaderKeyBytes: ByteArray,
		peerCoseKey: ByteArray?,
	): SessionCipher? {
		val sessionTransport = when (activeSidecarTransport) {
			SidecarTransport.L2CAP -> l2capProtocol()
			SidecarTransport.GATT, null -> selectedGattProtocol()
		}
		Logger(TAG).debug("Deriving session cipher using transport=${activeSidecarTransport ?: "selected GATT"}")
		val sessionProtocol = sessionTransport as? MdlTransportProtocolExtensions ?: return null
		val sessionCipher = sessionProtocol.getSessionCipher(engagementBytes, eReaderKeyBytes, peerCoseKey)
		sharedSessionTranscript = sessionProtocol.sessionTranscript
		return sessionCipher
	}

	private fun sidecarListener(transport: SidecarTransport) = object : TransportProtocol.Listener {
		override fun onConnecting() {
			if (!suppressSidecarCallbacks && activeSidecarTransport == null && !upstreamSidecarConnected) {
				upstreamListener?.onConnecting()
			}
		}

		override fun onConnected() {
			if (suppressSidecarCallbacks) return
			if (transport == SidecarTransport.L2CAP && l2capFallbackTriggered) {
				Logger(TAG).debug("Ignoring late L2CAP connection after GATT fallback started")
				disconnectSidecar(SidecarTransport.L2CAP)
				return
			}
			if (activeSidecarTransport != null && activeSidecarTransport != transport) {
				disconnectSidecar(transport)
				return
			}
			if (activeSidecarTransport == null) {
				activeSidecarTransport = transport
				deferredGattError = null
				l2capFallbackJob?.cancel()
				l2capFallbackJob = null
				if (!upstreamSidecarConnected) {
					upstreamSidecarConnected = true
					upstreamListener?.onConnected()
				}
				disconnectSidecar(if (transport == SidecarTransport.L2CAP) SidecarTransport.GATT else SidecarTransport.L2CAP)
			}
		}

		override fun onDisconnected() {
			if (suppressSidecarCallbacks || activeSidecarTransport != transport) return
			if (transport == SidecarTransport.L2CAP) {
				if (sessionCompleted) {
					Logger(TAG).debug("L2CAP peer closed after successful session completion; leaving GATT idle")
					activeSidecarTransport = null
					l2capFallbackTriggered = true
					disconnectSidecar(SidecarTransport.L2CAP)
					return
				}
				Logger(TAG).warn("Active L2CAP sidecar disconnected; continuing this session over GATT")
				activeSidecarTransport = null
				l2capFallbackTriggered = true
				startSelectedGattFallback()
			} else {
				upstreamListener?.onDisconnected()
			}
		}

		override fun onMessageReceived() {
			if (!suppressSidecarCallbacks && activeSidecarTransport == transport) upstreamListener?.onMessageReceived()
		}

		override fun onTransportSpecificSessionTermination() {
			if (!suppressSidecarCallbacks && activeSidecarTransport == transport) upstreamListener?.onTransportSpecificSessionTermination()
		}

		override fun onError(error: ProximityError) {
			if (transport == SidecarTransport.L2CAP) {
				Logger(TAG).warn("L2CAP sidecar error; selected GATT transport remains available: $error")
				if (!suppressSidecarCallbacks && activeSidecarTransport != SidecarTransport.GATT) {
					activeSidecarTransport = null
					l2capFallbackTriggered = true
					startSelectedGattFallback()
				}
			} else if (!suppressSidecarCallbacks) {
				when {
					activeSidecarTransport == SidecarTransport.GATT || l2capFallbackTriggered -> upstreamListener?.onError(error)
					activeSidecarTransport == SidecarTransport.L2CAP -> Unit
					l2capSidecarEnabled -> {
						deferredGattError = error
						Logger(TAG).warn("GATT fallback failed while L2CAP is still pending; deferring error: $error")
					}
					else -> upstreamListener?.onError(error)
				}
			}
		}
	}

	private fun disconnectSidecar(transport: SidecarTransport) {
		when (transport) {
			SidecarTransport.L2CAP -> l2capProtocol()?.disconnect()
			SidecarTransport.GATT -> {
				selectedGattFallbackJob?.cancel()
				selectedGattFallbackJob = null
				selectedGattStarted = false
				selectedGattProtocol()?.disconnect()
			}
		}
	}

	private fun startSelectedGattFallback() {
		if (suppressSidecarCallbacks || activeSidecarTransport != null) return
		l2capFallbackTriggered = true
		if (selectedGattStarted) {
			deferredGattError?.let { error ->
				deferredGattError = null
				upstreamListener?.onError(error)
			}
			return
		}
		selectedGattStarted = true
		l2capFallbackJob?.cancel()
		l2capFallbackJob = null
		disconnectSidecar(SidecarTransport.L2CAP)
		Logger(TAG).warn("Starting selected GATT fallback after L2CAP failure or disconnect")
		selectedGattFallbackJob = fallbackScope.launch {
			if (!suppressSidecarCallbacks && activeSidecarTransport == null) {
				configureListeners()
				selectedGattProtocol()?.connect()
			}
		}
	}

	private fun selectedGattProtocol(): BleTransportProtocol? = if (centralClientModeSelected) {
		centralClientModeTransportProtocol
	} else {
		peripheralServerModeTransportProtocol
	}

	private fun l2capProtocol(): BleTransportProtocol? = when {
		isEngagementPresenter && role == Role.WALLET -> peripheralServerModeTransportProtocol
		isEngagementPresenter && role == Role.VERIFIER -> centralClientModeTransportProtocol
		!isEngagementPresenter && role == Role.WALLET -> centralClientModeTransportProtocol
		else -> peripheralServerModeTransportProtocol
	}

	private fun l2capHasUsed(): Boolean = when (val protocol = l2capProtocol()) {
		is MdlCentralClientModeTransportProtocol -> protocol.hasUsedL2cap()
		is MdlPeripheralServerModeTransportProtocol -> protocol.hasUsedL2cap()
		else -> false
	}
}
