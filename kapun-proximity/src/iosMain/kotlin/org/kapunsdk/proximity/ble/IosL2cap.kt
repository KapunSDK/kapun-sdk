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

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCSignatureOverride
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import okio.Buffer
import org.kapunsdk.util.log.Logger
import platform.CoreBluetooth.CBCentralManager
import platform.CoreBluetooth.CBCentralManagerDelegateProtocol
import platform.CoreBluetooth.CBCentralManagerStatePoweredOn
import platform.CoreBluetooth.CBManagerStatePoweredOff
import platform.CoreBluetooth.CBManagerStateUnauthorized
import platform.CoreBluetooth.CBManagerStateUnsupported
import platform.CoreBluetooth.CBPeripheral
import platform.CoreBluetooth.CBPeripheralDelegateProtocol
import platform.CoreBluetooth.CBPeripheralManager
import platform.CoreBluetooth.CBPeripheralManagerDelegateProtocol
import platform.CoreBluetooth.CBPeripheralManagerStatePoweredOff
import platform.CoreBluetooth.CBPeripheralManagerStatePoweredOn
import platform.CoreBluetooth.CBPeripheralManagerStateUnauthorized
import platform.CoreBluetooth.CBPeripheralManagerStateUnsupported
import platform.CoreBluetooth.CBL2CAPChannel
import platform.CoreBluetooth.CBUUID
import platform.Foundation.NSError
import platform.Foundation.NSLock
import platform.Foundation.NSThread
import platform.darwin.NSObject
import platform.darwin.dispatch_async
import platform.darwin.dispatch_queue_create
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.uuid.Uuid

private const val TAG = "IosL2cap"
private const val MAX_MESSAGE_SIZE = 4 * 1024 * 1024
@OptIn(ExperimentalForeignApi::class)
private val serverCallbackQueue = dispatch_queue_create("org.kapunsdk.proximity.ble.IosL2cap.server", null)
@OptIn(ExperimentalForeignApi::class)
private val clientCallbackQueue = dispatch_queue_create("org.kapunsdk.proximity.ble.IosL2cap.client", null)

@OptIn(ExperimentalForeignApi::class)
private fun closeChannelStreams(channel: CBL2CAPChannel) {
	runCatching { channel.inputStream?.close() }
	runCatching { channel.outputStream?.close() }
}

@OptIn(ExperimentalForeignApi::class)
internal class IosL2capServer : BleL2capServer {
	private val delegate = IosL2capPeripheralDelegate(this)
	private val callbackQueue = serverCallbackQueue
	private var manager: CBPeripheralManager? = null
	private var psm: UShort? = null
	private var listenContinuation: kotlinx.coroutines.CancellableContinuation<Int>? = null
	private var listener: BleL2capListener? = null
	private var pendingChannel: CBL2CAPChannel? = null
	private var connection: IosL2capConnection? = null
	private var closed = false
	private var publishRequested = false

	override val isConnected: Boolean
		get() = connection?.isConnected == true

	override suspend fun listen(): Int = suspendCancellableCoroutine { continuation ->
		if (closed) {
			continuation.resumeWithException(IllegalStateException("L2CAP server is closed"))
			return@suspendCancellableCoroutine
		}
		val psmLocked = psm
		if (psmLocked != null) {
			continuation.resume(psmLocked.toInt())
			return@suspendCancellableCoroutine
		}
		listenContinuation = continuation
		continuation.invokeOnCancellation { close() }
		manager = CBPeripheralManager(delegate, callbackQueue)
	}

	internal fun onStateUpdated(peripheral: CBPeripheralManager) {
		if (closed || publishRequested) return
		when (peripheral.state) {
			CBPeripheralManagerStatePoweredOn -> {
				publishRequested = true
				Logger(TAG).debug("Publishing CoreBluetooth L2CAP CoC listener")
				peripheral.publishL2CAPChannelWithEncryption(false)
			}
			CBPeripheralManagerStatePoweredOff,
			CBPeripheralManagerStateUnauthorized,
			CBPeripheralManagerStateUnsupported -> {
				val continuation = listenContinuation ?: return
				listenContinuation = null
				continuation.resumeWithException(IllegalStateException("CoreBluetooth peripheral manager is unavailable: ${peripheral.state}"))
			}
		}
	}

	internal fun onPublished(peripheral: CBPeripheralManager, psm: UShort, error: NSError?) {
		if (error != null) {
			val continuation = listenContinuation
			listenContinuation = null
			Logger(TAG).warn("Unable to publish CoreBluetooth L2CAP channel: ${error.localizedDescription}")
			continuation?.resumeWithException(IllegalStateException(error.localizedDescription))
			return
		}
		if (closed) {
			Logger(TAG).debug("L2CAP listener closed while publish was pending; unpublishing psm=${psm.toInt()}")
			peripheral.unpublishL2CAPChannel(psm)
			return
		}
		this.psm = psm
		Logger(TAG).debug("CoreBluetooth L2CAP listener ready: psm=${psm.toInt()}")
		val continuation = listenContinuation
		listenContinuation = null
		continuation?.resume(psm.toInt())
	}

	internal fun onChannelOpened(channel: CBL2CAPChannel?, error: NSError?) {
		if (closed) {
			channel?.let(::closeChannelStreams)
			return
		}
		if (error != null || channel == null) {
			val message = error?.localizedDescription ?: "CoreBluetooth opened a null L2CAP channel"
			Logger(TAG).warn("Incoming L2CAP channel failed: $message")
			listener?.onError(message)
			return
		}
		if (connection != null || pendingChannel != null) {
			Logger(TAG).warn("Closing an extra incoming L2CAP channel")
			closeChannelStreams(channel)
			return
		}
		if (listener == null) {
			pendingChannel = channel
			Logger(TAG).debug("L2CAP peer arrived before accept was armed; retaining channel")
			return
		}
		attachChannel(channel)
	}

	override fun accept(listener: BleL2capListener) {
		if (closed) return
		this.listener = listener
		pendingChannel?.let {
			pendingChannel = null
			attachChannel(it)
		}
	}

	private fun attachChannel(channel: CBL2CAPChannel) {
		val currentListener = listener ?: return
		connection = IosL2capConnection(channel, currentListener)
		Logger(TAG).debug("CoreBluetooth L2CAP server accepted a peer")
		currentListener.onConnected()
	}

	override fun writeMessage(data: ByteArray) {
		(connection ?: throw IllegalStateException("L2CAP is not connected")).writeMessage(data)
	}

	override fun close() {
		if (closed) return
		closed = true
		listenContinuation?.let {
			listenContinuation = null
			it.cancel()
		}
		connection?.close()
		connection = null
		pendingChannel?.let(::closeChannelStreams)
		pendingChannel = null
		listener = null
		val currentManager = manager
		val publishedPsm = psm
		if (currentManager != null && publishedPsm != null) {
			dispatch_async(callbackQueue) { currentManager.unpublishL2CAPChannel(publishedPsm) }
		}
		psm = null
		manager = null
	}
}

@OptIn(ExperimentalForeignApi::class)
internal class IosL2capClient : BleL2capClient {
	private val delegate = IosL2capCentralDelegate(this)
	private val callbackQueue = clientCallbackQueue
	private var manager: CBCentralManager? = null
	private var peripheral: CBPeripheral? = null
	private var listener: BleL2capListener? = null
	private var connection: IosL2capConnection? = null
	private var targetServiceUuid: Uuid? = null
	private var targetPsm: UShort? = null
	private var closed = false
	private var disconnectReported = false
	private var scanStarted = false
	private var l2capChannelOpened = false

	override val isConnected: Boolean
		get() = connection?.isConnected == true

	override fun connect(
		serviceUuid: Uuid,
		psm: Int,
		deviceMacAddress: String?,
		listener: BleL2capListener,
	) {
		if (deviceMacAddress != null) {
			throw IllegalArgumentException("iOS does not expose BLE MAC addresses")
		}
		closed = false
		disconnectReported = false
		scanStarted = false
		l2capChannelOpened = false
		this.listener = listener
		targetServiceUuid = serviceUuid
		targetPsm = psm.toUShort()
		manager = CBCentralManager(delegate, callbackQueue)
	}

	internal fun onStateUpdated(central: CBCentralManager) {
		if (closed || peripheral != null || scanStarted) return
		if (central.state == CBManagerStatePoweredOff ||
			central.state == CBManagerStateUnauthorized ||
			central.state == CBManagerStateUnsupported
		) {
			onConnectionFailed(null)
			return
		}
		if (central.state != CBCentralManagerStatePoweredOn) return
		val serviceUuid = targetServiceUuid ?: return
		scanStarted = true
		Logger(TAG).debug("Scanning for L2CAP peer service=$serviceUuid")
		central.scanForPeripheralsWithServices(
			listOf(CBUUID.UUIDWithString(serviceUuid.toString())),
			null,
		)
	}

	internal fun onDiscovered(central: CBCentralManager, discovered: CBPeripheral) {
		if (closed || peripheral != null) return
		peripheral = discovered
		central.stopScan()
		discovered.delegate = delegate
		Logger(TAG).debug("Found L2CAP peer; connecting")
		central.connectPeripheral(discovered, null)
	}

	internal fun onConnected(connectedPeripheral: CBPeripheral) {
		if (closed) return
		peripheral = connectedPeripheral
		connectedPeripheral.delegate = delegate
		val psm = targetPsm ?: run {
			listener?.onError("L2CAP PSM is missing")
			return
		}
		Logger(TAG).debug("Opening CoreBluetooth L2CAP channel: psm=${psm.toInt()}")
		connectedPeripheral.openL2CAPChannel(psm)
	}

	internal fun onChannelOpened(channel: CBL2CAPChannel?, error: NSError?) {
		if (error != null || channel == null) {
			channel?.let(::closeChannelStreams)
			val message = error?.localizedDescription ?: "CoreBluetooth opened a null L2CAP channel"
			Logger(TAG).warn("Outgoing L2CAP channel failed: $message")
			listener?.onError(message)
			return
		}
		if (closed) {
			closeChannelStreams(channel)
			return
		}
		l2capChannelOpened = true
		val currentListener = listener ?: return
		connection = IosL2capConnection(channel, object : BleL2capListener {
			override fun onConnected() = currentListener.onConnected()
			override fun onMessageReceived(data: ByteArray) = currentListener.onMessageReceived(data)
			override fun onError(message: String) {
					cancelPeripheralConnection()
				currentListener.onError(message)
			}
			override fun onDisconnected() {
					connection?.close()
					connection = null
					cancelPeripheralConnection()
				notifyDisconnected()
			}
		})
		Logger(TAG).debug("CoreBluetooth L2CAP client connected")
		currentListener.onConnected()
	}

	internal fun onConnectionFailed(error: NSError?) {
		if (!closed) listener?.onError(error?.localizedDescription ?: "Unable to connect to L2CAP peer")
	}

	internal fun onDisconnected(error: NSError?) {
		if (closed || disconnectReported) return
		if (!l2capChannelOpened) {
			onConnectionFailed(error)
			return
		}
		connection?.close()
		connection = null
		notifyDisconnected()
	}

	private fun notifyDisconnected() {
		if (!closed && !disconnectReported) {
			disconnectReported = true
			listener?.onDisconnected()
		}
	}

	override fun writeMessage(data: ByteArray) {
		(connection ?: throw IllegalStateException("L2CAP is not connected")).writeMessage(data)
	}

	override fun close() {
		if (closed) return
		closed = true
		connection?.close()
		connection = null
		val currentManager = manager
		val connectedPeripheral = peripheral
		if (currentManager != null) {
			dispatch_async(callbackQueue) {
				connectedPeripheral?.let { currentManager.cancelPeripheralConnection(it) }
				currentManager.stopScan()
			}
		}
		peripheral = null
		manager = null
		scanStarted = false
		listener = null
	}

	private fun cancelPeripheralConnection() {
		val currentManager = manager ?: return
		val connectedPeripheral = peripheral ?: return
		dispatch_async(callbackQueue) {
			currentManager.cancelPeripheralConnection(connectedPeripheral)
		}
	}
}

@OptIn(ExperimentalForeignApi::class)
private class IosL2capConnection(
	// Keep the CoreBluetooth channel alive for the lifetime of its streams.
	private val channel: CBL2CAPChannel,
	private val listener: BleL2capListener,
) : BleL2capConnection {
	private val input = channel.inputStream ?: error("CoreBluetooth L2CAP input stream is unavailable")
	private val output = channel.outputStream ?: error("CoreBluetooth L2CAP output stream is unavailable")
	private val outputLock = NSLock()
	private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
	private var closed = false
	private var pendingInput = byteArrayOf()

	init {
		input.open()
		output.open()
		scope.launch { readMessages() }
	}

	override val isConnected: Boolean
		get() = !closed

	override fun writeMessage(data: ByteArray) {
		if (closed) throw IllegalStateException("L2CAP is not connected")
		// Android's DataOutputStream.writeInt uses the same 4-byte big-endian prefix.
		val frame = Buffer().writeInt(data.size).write(data).readByteArray()

		outputLock.lock()
		try {
			var offset = 0
			while (offset < frame.size && !closed) {
				val written = frame.usePinned {
					output.write(it.addressOf(offset).reinterpret<UByteVar>(), (frame.size - offset).toULong())
				}.toInt()
				if (written < 0) throw IllegalStateException(output.streamError?.localizedDescription ?: "L2CAP stream write failed")
				if (written == 0) {
					NSThread.sleepForTimeInterval(0.01)
					continue
				}
				offset += written
			}
			if (closed) throw IllegalStateException("L2CAP channel closed while writing")
		} finally {
			outputLock.unlock()
		}
		Logger(TAG).debug("CoreBluetooth L2CAP sent message: bytes=${data.size}")
	}

	private suspend fun readMessages() {
		val buffer = ByteArray(4096)
		try {
			while (!closed) {
				val bytesRead = buffer.usePinned {
					input.read(it.addressOf(0).reinterpret<UByteVar>(), buffer.size.toULong())
				}.toInt()
				when {
					bytesRead < 0 -> {
						closeFromRemote()
						return
					}
					bytesRead == 0 -> delay(10)
					else -> consume(buffer.copyOfRange(0, bytesRead))
				}
			}
		} catch (error: Exception) {
			if (!closed) {
				Logger(TAG).warn("CoreBluetooth L2CAP read failed: ${error.message}")
				closeAfterError(error.message ?: "L2CAP stream read failed")
			}
		}
	}

	private fun consume(data: ByteArray) {
		val combined = pendingInput + data
		var offset = 0
		while (!closed && combined.size - offset >= 4) {
			val size = Buffer().write(combined, offset, 4).readInt()
			if (size !in 0..MAX_MESSAGE_SIZE) {
				closeAfterError("Invalid L2CAP message length: $size")
				return
			}
			if (combined.size - offset < size + 4) break
			listener.onMessageReceived(combined.copyOfRange(offset + 4, offset + 4 + size))
			offset += size + 4
		}
		pendingInput = combined.copyOfRange(offset, combined.size)
	}

	private fun closeFromRemote() {
		if (closed) return
		closeStreams()
		listener.onDisconnected()
	}

	private fun closeAfterError(message: String) {
		if (closed) return
		closeStreams()
		listener.onError(message)
	}

	private fun closeStreams() {
		closed = true
		scope.cancel()
		runCatching { input.close() }
		runCatching { output.close() }
	}

	override fun close() {
		if (closed) return
		closeStreams()
	}
}

private class IosL2capPeripheralDelegate(
	private val server: IosL2capServer,
) : NSObject(), CBPeripheralManagerDelegateProtocol {
	override fun peripheralManagerDidUpdateState(peripheral: CBPeripheralManager) {
		server.onStateUpdated(peripheral)
	}

	@ObjCSignatureOverride
	override fun peripheralManager(
		peripheral: CBPeripheralManager,
		didPublishL2CAPChannel: UShort,
		error: NSError?,
	) {
		server.onPublished(peripheral, didPublishL2CAPChannel, error)
	}

	@ObjCSignatureOverride
	override fun peripheralManager(
		peripheral: CBPeripheralManager,
		didOpenL2CAPChannel: CBL2CAPChannel?,
		error: NSError?,
	) {
		server.onChannelOpened(didOpenL2CAPChannel, error)
	}
}

private class IosL2capCentralDelegate(
	private val client: IosL2capClient,
) : NSObject(), CBCentralManagerDelegateProtocol, CBPeripheralDelegateProtocol {
	override fun centralManagerDidUpdateState(central: CBCentralManager) {
		client.onStateUpdated(central)
	}

	@ObjCSignatureOverride
	override fun centralManager(
		central: CBCentralManager,
		didDiscoverPeripheral: CBPeripheral,
		advertisementData: Map<Any?, *>,
		RSSI: platform.Foundation.NSNumber,
	) {
		client.onDiscovered(central, didDiscoverPeripheral)
	}

	override fun centralManager(central: CBCentralManager, didConnectPeripheral: CBPeripheral) {
		client.onConnected(didConnectPeripheral)
	}

	@ObjCSignatureOverride
	override fun centralManager(
		central: CBCentralManager,
		didFailToConnectPeripheral: CBPeripheral,
		error: NSError?,
	) {
		client.onConnectionFailed(error)
	}

	@ObjCSignatureOverride
	override fun centralManager(
		central: CBCentralManager,
		didDisconnectPeripheral: CBPeripheral,
		error: NSError?,
	) {
		client.onDisconnected(error)
	}

	@ObjCSignatureOverride
	override fun peripheral(
		peripheral: CBPeripheral,
		didOpenL2CAPChannel: CBL2CAPChannel?,
		error: NSError?,
	) {
		client.onChannelOpened(didOpenL2CAPChannel, error)
	}
}
