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

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.os.Build
import android.os.ParcelUuid
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import org.kapunsdk.util.log.Logger
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

private const val MAX_MESSAGE_SIZE = 4 * 1024 * 1024
private const val TAG = "BluetoothL2cap"

@SuppressLint("MissingPermission")
internal class BluetoothL2capServer(private val bm: BluetoothManager) : BleL2capServer {
	private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
	@Volatile private var serverSocket: BluetoothServerSocket? = null
	@Volatile private var socket: BluetoothSocket? = null
	@Volatile private var ioJob: Job? = null
	@Volatile private var closed = false
	private val outputLock = Any()

	override val isConnected: Boolean
		get() = socket?.isConnected == true

	override suspend fun listen(): Int {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
			Logger(TAG).warn("L2CAP listen unavailable: Android 10 or later is required")
			throw IOException("LE L2CAP CoC requires Android 10 or later")
		}
		val adapter = bm.adapter ?: run {
			Logger(TAG).warn("L2CAP listen failed: Bluetooth adapter is unavailable")
			throw IOException("Bluetooth is unavailable")
		}
		if (!adapter.isEnabled) {
			Logger(TAG).warn("L2CAP listen failed: Bluetooth is turned off")
			throw IOException("Bluetooth is turned off")
		}
		Logger(TAG).debug("Opening L2CAP CoC server socket")
		val listeningSocket = adapter.listenUsingInsecureL2capChannel()
		serverSocket = listeningSocket
		closed = false
		Logger(TAG).debug("L2CAP CoC server listening: psm=${listeningSocket.psm}")
		return listeningSocket.psm
	}

	override fun accept(listener: BleL2capListener) {
		val listeningSocket = serverSocket ?: run {
			listener.onError("L2CAP server socket is not listening")
			return
		}
		if (ioJob?.isActive == true) {
			Logger(TAG).warn("L2CAP accept ignored: an accept/read job is already active")
			return
		}
		Logger(TAG).debug("L2CAP server waiting for a peer")
		ioJob = ioScope.launch {
			var acceptedSocket: BluetoothSocket? = null
			try {
				val accepted = runInterruptible { listeningSocket.accept() }
				acceptedSocket = accepted
				if (closed) {
					accepted.close()
					return@launch
				}
				socket = accepted
				Logger(TAG).debug("L2CAP server accepted a peer")
				runCatching { listeningSocket.close() }
				listener.onConnected()
				runInterruptible { readMessages(accepted, listener) }
			} catch (e: CancellationException) {
				Logger(TAG).debug("L2CAP server accept/read job cancelled")
			} catch (e: Exception) {
				if (!closed) {
					Logger(TAG).warn("L2CAP server accept failed: ${e.message ?: e::class.java.simpleName}")
					listener.onError(e.message ?: e::class.java.simpleName)
				}
			} finally {
				runCatching { listeningSocket.close() }
				if (serverSocket === listeningSocket) serverSocket = null
				acceptedSocket?.let { runCatching { it.close() } }
				if (socket === acceptedSocket) socket = null
				Logger(TAG).debug("L2CAP server channel closed (explicitClose=$closed)")
				if (!closed) listener.onDisconnected()
			}
		}
	}

	override fun writeMessage(data: ByteArray) {
		val currentSocket = socket ?: throw IOException("L2CAP is not connected")
		synchronized(outputLock) {
			val output = DataOutputStream(currentSocket.outputStream)
			output.writeInt(data.size)
			output.write(data)
			output.flush()
			Logger(TAG).debug("L2CAP server sent message: bytes=${data.size}")
		}
	}

	override fun close() {
		Logger(TAG).debug("Closing L2CAP server socket and channel")
		closed = true
		ioJob?.cancel()
		val listeningSocket = serverSocket
		val connectedSocket = socket
		serverSocket = null
		socket = null
		// Job cancellation is cooperative; closing the sockets reliably releases blocking accept/read calls.
		runCatching { listeningSocket?.close() }
		runCatching { connectedSocket?.close() }
	}
}

@SuppressLint("MissingPermission")
internal class BluetoothL2capClient(private val bm: BluetoothManager) : BleL2capClient {
	private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
	@Volatile private var scanner: BluetoothLeScanner? = null
	@Volatile private var socket: BluetoothSocket? = null
	@Volatile private var scanCallback: ScanCallback? = null
	@Volatile private var ioJob: Job? = null
	@Volatile private var connecting = false
	@Volatile private var closed = false
	private val outputLock = Any()

	override val isConnected: Boolean
		get() = socket?.isConnected == true

	override fun connect(
		serviceUuid: Uuid,
		psm: Int,
		deviceMacAddress: String?,
		listener: BleL2capListener,
	) {
		val adapter = bm.adapter ?: throw IOException("Bluetooth is unavailable")
		if (!adapter.isEnabled) {
			Logger(TAG).warn("L2CAP connect failed: Bluetooth is turned off")
			throw IOException("Bluetooth is turned off")
		}
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
			Logger(TAG).warn("L2CAP connect unavailable: Android 10 or later is required")
			throw IOException("LE L2CAP CoC requires Android 10 or later")
		}
		Logger(TAG).debug("Starting L2CAP connection: psm=$psm service=$serviceUuid")
		closed = false
		if (deviceMacAddress != null) {
			connectToDevice(adapter.getRemoteDevice(deviceMacAddress), psm, listener)
			return
		}

		val leScanner = adapter.bluetoothLeScanner ?: throw IOException("BLE scanning is unavailable")
		scanner = leScanner
		val filter = ScanFilter.Builder()
			.setServiceUuid(ParcelUuid(serviceUuid.toJavaUuid()))
			.build()
		val settings = ScanSettings.Builder()
			.setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
			.build()
		connecting = false
		closed = false
		val callback = object : ScanCallback() {
			override fun onScanResult(callbackType: Int, result: ScanResult) {
				if (connecting || closed) return
				connecting = true
				Logger(TAG).debug("Found L2CAP peer in BLE scan: rssi=${result.rssi}")
				runCatching { leScanner.stopScan(this) }
				scanCallback = null
				connectToDevice(result.device, psm, listener)
			}

			override fun onScanFailed(errorCode: Int) {
				if (!closed) {
					Logger(TAG).warn("L2CAP peer scan failed: errorCode=$errorCode")
					listener.onError("BLE scan failed with error code $errorCode")
				}
			}
		}
		scanCallback = callback
		Logger(TAG).debug("Starting BLE scan to locate L2CAP peer: service=$serviceUuid")
		leScanner.startScan(listOf(filter), settings, callback)
	}

	private fun connectToDevice(device: android.bluetooth.BluetoothDevice, psm: Int, listener: BleL2capListener) {
		connecting = true
		ioJob = ioScope.launch {
			var connectedSocket: BluetoothSocket? = null
			try {
				val connected = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
					device.createInsecureL2capChannel(psm)
				} else {
					Logger(TAG).warn("L2CAP requires API-Level 29")
					listener.onError("L2CAP not supported")
					return@launch
				}
				connectedSocket = connected
				socket = connected
				runInterruptible { connected.connect() }
				if (closed) {
					connected.close()
					return@launch
				}
				Logger(TAG).debug("L2CAP client channel connected: psm=$psm")
				listener.onConnected()
				runInterruptible { readMessages(connected, listener) }
			} catch (e: CancellationException) {
				Logger(TAG).debug("L2CAP client connect/read job cancelled")
			} catch (e: Exception) {
				if (!closed) {
					Logger(TAG).warn("L2CAP client connection failed: ${e.message ?: e::class.java.simpleName}")
					listener.onError(e.message ?: e::class.java.simpleName)
				}
			} finally {
				connectedSocket?.let { runCatching { it.close() } }
				if (socket === connectedSocket) socket = null
				Logger(TAG).debug("L2CAP client channel closed (explicitClose=$closed)")
				if (!closed) listener.onDisconnected()
			}
		}
	}

	override fun writeMessage(data: ByteArray) {
		val currentSocket = socket ?: throw IOException("L2CAP is not connected")
		synchronized(outputLock) {
			val output = DataOutputStream(currentSocket.outputStream)
			output.writeInt(data.size)
			output.write(data)
			output.flush()
			Logger(TAG).debug("L2CAP client sent message: bytes=${data.size}")
		}
	}

	override fun close() {
		Logger(TAG).debug("Closing L2CAP client scan and channel")
		closed = true
		ioJob?.cancel()
		runCatching { scanner?.let { scan -> scanCallback?.let(scan::stopScan) } }
		val connectedSocket = socket
		socket = null
		scanner = null
		scanCallback = null
		connecting = false
		// Job cancellation is cooperative; closing the socket reliably releases blocking connect/read calls.
		runCatching { connectedSocket?.close() }
	}
}

private fun readMessages(socket: BluetoothSocket, listener: BleL2capListener) {
	val input = DataInputStream(socket.inputStream)
	while (true) {
		val size = try {
			input.readInt()
		} catch (_: EOFException) {
			return
		}
		if (size < 0 || size > MAX_MESSAGE_SIZE) {
			throw IOException("Invalid L2CAP message length: $size")
		}
		val data = ByteArray(size)
		input.readFully(data)
		Logger(TAG).debug("L2CAP received message: bytes=$size")
		listener.onMessageReceived(data)
	}
}
