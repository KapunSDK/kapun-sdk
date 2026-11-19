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
package org.kapunsdk.proximity.verifier

import org.kapunsdk.proximity.ProximityProtocol
import org.kapunsdk.proximity.ProximityProcessEvent
import org.kapunsdk.proximity.ble.ProximityBleOptions
import org.kapunsdk.proximity.ProximityError
import org.kapunsdk.proximity.documents.DocumentRequest
import org.kapunsdk.proximity.documents.DocumentRequester
import org.kapunsdk.proximity.protocol.EngagementBuilder
import org.kapunsdk.proximity.protocol.TransportProtocol
import org.kapunsdk.proximity.protocol.mdl.MdlCoseKey
import org.kapunsdk.proximity.protocol.mdl.MdlEngagement
import org.kapunsdk.proximity.protocol.mdl.MdlEngagementBuilder
import org.kapunsdk.proximity.protocol.mdl.MdlSessionData
import org.kapunsdk.proximity.protocol.mdl.MdlSessionEstablishment
import org.kapunsdk.proximity.protocol.mdl.MdlTransportProtocol
import org.kapunsdk.proximity.protocol.mdl.MdlTransportProtocolExtensions
import org.kapunsdk.proximity.protocol.openid4vp.OpenId4VpEngagementBuilder
import org.kapunsdk.proximity.protocol.openid4vp.OpenId4VpTransportProtocol
import org.kapunsdk.util.extensions.json
import org.kapunsdk.util.extensions.toCbor
import org.kapunsdk.util.log.Logger
import org.kapunsdk.proximity.util.ProximityMdlUtils
import org.kapunsdk.proximity.util.logPayloadDebug
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import uniffi.kapun_crypto_rust.EphemeralKey
import uniffi.kapun_crypto_rust.KeyType
import uniffi.kapun_crypto_rust.Role
import uniffi.kapun_crypto_rust.SessionCipher
import uniffi.kapun_crypto_rust.base64UrlEncode
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.encodeCbor
// The new path can require canonical key bytes without changing MDL's key-encoding branch.
import uniffi.kapun_util_rust.encodeCborCanonical
import kotlin.uuid.Uuid

/**
 * @param T The type of the verification result, which is returned by the [documentRequester] in its [DocumentRequester.verifySubmittedDocuments] method
 */
class ProximityVerifier<T> private constructor(
	private val protocol: ProximityProtocol,
	private val scope: CoroutineScope,
	private val engagementBuilder: EngagementBuilder?,
	private val transportProtocol: TransportProtocol,
	private val documentRequester: DocumentRequester<T>,
	private var sessionCipher: SessionCipher? = null,
	private var isDcApi : Boolean = true,
	private val readerKey: Value? = null,
	/** Stable identifier for this created verifier process. */
	val processId: Uuid = Uuid.random(),
) {
	// OPENID4VP_OVER_ISO replaces this bundle on reset so its transport, engagement and key stay paired.
	// Keeping recreation behind that selection avoids changing the lifecycle expected by MDL consumers.
	private var activeSession = VerifierSession(readerKey, engagementBuilder, transportProtocol)
	private var reverseSessionFactory: (() -> VerifierSession)? = null
	private var sessionNeedsRecreation: Boolean = false
	// Reattach the same callbacks to a recreated profile transport rather than retaining the old session.
	private var transportListener: TransportProtocol.Listener
	private val operationJob = SupervisorJob(scope.coroutineContext[Job])
	private val operationScope = CoroutineScope(scope.coroutineContext + operationJob)

	companion object {
		private const val TAG = "ProximityVerifier"

		fun <T> createReverse(protocol: ProximityProtocol,
							  scope: CoroutineScope,
							  verifierName: String,
							  requester: DocumentRequester<T>,
							  serviceUuid: String,
							  preferDcApi: Boolean = true,
							  peripheralServerUuid: String? = null,
							  keyType: KeyType = KeyType.ED25519,
							  bleOptions: ProximityBleOptions = ProximityBleOptions.Default,
							  enableL2cap: Boolean = true): ProximityVerifier<T> {
			val publicKey = EphemeralKey(Role.SK_READER, keyType)
			return when (protocol) {
				ProximityProtocol.OPENID4VP_OVER_ISO -> {
					// A dedicated factory is the profile boundary: MDL and OPENID4VP retain their existing setup.
					val effectiveServiceUuid = peripheralServerUuid?.let { Uuid.parse(it) } ?: Uuid.parse(serviceUuid)
					val createSession = {
						createReverseOpenId4VpOverIsoSession(verifierName, effectiveServiceUuid, bleOptions)
					}
					val session = createSession()
					// This selection cannot fall back to the native mDL application layer; retain its factory for freshness.
					ProximityVerifier(protocol, scope, session.engagementBuilder, session.transportProtocol,
						requester, readerKey = session.readerKey, isDcApi = true).also {
						it.reverseSessionFactory = createSession
					}
				}
				ProximityProtocol.MDL -> {
					val coseKey = MdlCoseKey.fromPublicKeyBytes(publicKey.publicKey(), keyType)
					val coseKeyEncoded = encodeCbor(coseKey)

					val transportProtocol = MdlTransportProtocol(
						TransportProtocol.Role.VERIFIER,
						Uuid.parse(serviceUuid),
						peripheralServerUuid?.let { Uuid.parse(it)},
						publicKey,
						options = bleOptions,
						enableL2cap = enableL2cap,
						isEngagementPresenter = true,
					)
					val engagementBuilder = MdlEngagementBuilder(
						"",
						coseKeyEncoded,
						Uuid.parse(serviceUuid),
						peripheralServerUuid?.let { Uuid.parse(it) },
						true,
						transportProtocol.peripheralServerModeTransportProtocol != null,
						capabilities = ProximityMdlUtils.defaultDcApiCapabilities()
					)
					ProximityVerifier(protocol, scope, engagementBuilder, transportProtocol, requester, readerKey = coseKey, isDcApi = preferDcApi)
				}
				ProximityProtocol.OPENID4VP -> {
					val serviceUuid = Uuid.random()
					val engagementBuilder = OpenId4VpEngagementBuilder(verifierName,  base64UrlEncode(publicKey.publicKey()), serviceUuid)
					val transportProtocol = OpenId4VpTransportProtocol(
						TransportProtocol.Role.VERIFIER,
						serviceUuid,
						requester
					)
					ProximityVerifier(protocol, scope, engagementBuilder, transportProtocol, requester)
				}
			}
		}
		fun <T> create(
			protocol: ProximityProtocol,
			scope: CoroutineScope,
			verifierName: String,
			requester: DocumentRequester<T>,
			qrcodeData: String? = null,
			preferDcApi: Boolean = true,
			keyType: KeyType = KeyType.ED25519,
			bleOptions: ProximityBleOptions = ProximityBleOptions.Default
		): ProximityVerifier<T>? {
			val publicKey = EphemeralKey(Role.SK_READER, keyType)
			return when (protocol) {
				ProximityProtocol.OPENID4VP_OVER_ISO -> throw UnsupportedOperationException("Direct ISO profile engagement is outside this demo")
				ProximityProtocol.MDL -> {
					val coseKey = MdlCoseKey.fromPublicKeyBytes(publicKey.publicKey(), keyType)
					val engagementData = qrcodeData ?: return null
					val deviceEngagement = MdlEngagement.fromQrCode(engagementData)
					val transportProtocol = MdlTransportProtocol(
						TransportProtocol.Role.VERIFIER,
						deviceEngagement?.centralClientUuid,
						deviceEngagement?.peripheralServerUuid,
						publicKey,
						options = bleOptions,
						l2capPsm = deviceEngagement?.l2capPsm,
						isEngagementPresenter = false,
					)
					ProximityVerifier(protocol, scope, deviceEngagement, transportProtocol, requester, readerKey = coseKey, isDcApi = preferDcApi)
				}
				ProximityProtocol.OPENID4VP -> {
					val serviceUuid = Uuid.random()
					val engagementBuilder = OpenId4VpEngagementBuilder(verifierName,  base64UrlEncode(publicKey.publicKey()), serviceUuid)
					val transportProtocol = OpenId4VpTransportProtocol(
						TransportProtocol.Role.VERIFIER,
						serviceUuid,
						requester
					)
					ProximityVerifier(protocol, scope, engagementBuilder, transportProtocol, requester)
				}
			}
		}

		@OptIn(DelicateCoroutinesApi::class)
		fun <T> create(
			protocol: ProximityProtocol,
			verifierName: String,
			requester: DocumentRequester<T>,
		): ProximityVerifier<T>? {
			return create(protocol, GlobalScope, verifierName, requester)
		}
	}

	private val verifierStateMutable = MutableStateFlow<ProximityVerifierState>(ProximityVerifierState.Initial)
	val verifierState = verifierStateMutable.asStateFlow()
	/** Verifier state events tagged with [processId]. */
	val events = verifierStateMutable.map { state -> ProximityProcessEvent(processId, state) }

	init {
		transportProtocol.setListener(
			object : TransportProtocol.Listener {
					override fun onConnecting() {
					publishState(ProximityVerifierState.Connecting)
				}

				 override fun onConnected() {
					if (!publishState(ProximityVerifierState.Connected)) {
						return
					}

					// Share ISO connection sequencing, not OPENID4VP's separate GATT request exchange.
					if(protocol == ProximityProtocol.MDL || protocol == ProximityProtocol.OPENID4VP_OVER_ISO) {
						// We don't have a device engagement yet so wait for the first package
						// from the wallet
						// After a profile reset, wait on the new engagement rather than the constructor's old one.
						when(val engagementBuilder = activeSession.engagementBuilder) {
							is MdlEngagementBuilder -> return
							is MdlEngagement -> {
								sessionCipher = (transportProtocol as MdlTransportProtocolExtensions).getSessionCipher(engagementBuilder.originalData, encodeCbor(readerKey.toCbor()), engagementBuilder.coseKey)
								requestDocument()
							}
						}
					}
				}

					override fun onDisconnected() {
					cancelPendingOperations()
					publishState(ProximityVerifierState.Disconnected)
				}

				override fun onMessageReceived() {
					// Profile sessions can replace their transport; legacy paths keep the same active transport.
					val message = activeSession.transportProtocol.getMessage()
					if (message != null) {
						processMessageReceived(message)
					} else {
						cancelPendingOperations()
						publishState(ProximityVerifierState.Error(ProximityError.InvalidData("Received message is null")))
					}
				}

				override fun onTransportSpecificSessionTermination() {

				}

				override fun onError(error: ProximityError) {
					cancelPendingOperations()
					publishState(ProximityVerifierState.Error(error))
				}
			// Capture callbacks for profile-only recreation; no separate transport stack is needed.
			}.also { transportListener = it }
		)
	}

	 fun requestDocument() {
		if (verifierStateMutable.value.isTerminal()) {
			return
		}
		Logger(TAG).debug("requestDocument: building document request")
		operationScope.launch {
			try {
				// Use the current session's transcript: its Origin binds the OpenID4VP request to these keys.
			// An active bundle prevents profile resets from accidentally signing for the previous session.
			val sessionTranscript = (activeSession.transportProtocol as MdlTransportProtocolExtensions).sessionTranscript ?: run {
					publishState(ProximityVerifierState.Error(ProximityError.InvalidData("failed to get session transcript")))
					return@launch
				}
				val origin = ProximityMdlUtils.buildIsoOriginFromSessionTranscript(sessionTranscript)
				Logger(TAG).debug("requestDocument: calling document requester")
				val documentRequest = documentRequester.createDocumentRequest(origin)
				Logger(TAG).debug("requestDocument: document request created type=${documentRequest::class.simpleName}")
				when (documentRequest) {
					is DocumentRequest.Mdl -> {
					// Reject native mDL only on the new path; changing this globally would remove MDL behavior.
					if (protocol == ProximityProtocol.OPENID4VP_OVER_ISO) {
						publishState(ProximityVerifierState.Error(ProximityError.InvalidState("ISO profile requires DocumentRequest.OpenId4Vp")))
						return@launch
					}
						isDcApi = false
					}
					is DocumentRequest.OpenId4Vp -> {
						isDcApi = true
						// convert our custom class to the DC-API object
						val dcRequest = documentRequest.asDcRequest()
						val serializedDcRequest = json.encodeToString(dcRequest)
						val currentCipher = sessionCipher ?: run {
							publishState(ProximityVerifierState.Error(ProximityError.InvalidData("no session cipher")))
							return@launch
						}
					// A recreated profile session must use its new reader key, not the constructor's original key.
					activeSession.readerKey ?: run {
							publishState(ProximityVerifierState.Error(ProximityError.InvalidData("reader key is null")))
							return@launch
						}
						val encryptedData = currentCipher.encrypt(serializedDcRequest.encodeToByteArray()) ?: run {
							publishState(ProximityVerifierState.Error(ProximityError.InvalidData("failed to encrypt data")))
							return@launch
						}
					// The profile needs byte-identical reader keys in engagement and SessionEstablishment.
					// Its encoding branch is explicit, while MDL keeps its existing key serialization.
					val encodedReaderKey = if (protocol == ProximityProtocol.OPENID4VP_OVER_ISO) {
						activeSession.readerKey?.let { encodeCborCanonical(it) } ?: return@launch
					} else encodeCbor(readerKey.toCbor())
					var readerKeyTagged = (24 to encodedReaderKey).toCbor()
						// In the session establishment data package, we need to transmit the other part of the key (ours)
						val sessionEstablishment = MdlSessionEstablishment(readerKeyTagged, encryptedData, true)
						Logger(TAG).debug("requestDocument: sending session establishment, plaintextBytes=${serializedDcRequest.length}")
					// Send over the paired ISO transport, not OPENID4VP's characteristic-read exchange.
						activeSession.transportProtocol.sendMessage(sessionEstablishment.asCbor())
						Logger(TAG).debug("requestDocument: session establishment sent")
						publishState(ProximityVerifierState.AwaitingDocuments)
					}
				}
			} catch (e: CancellationException) {
				throw e
			} catch (e: Exception) {
				Logger(TAG).error("requestDocument failed: ${e::class.simpleName}: ${e.message}")
				throw e
			}

		}
	}

	@Throws(Exception::class)
	fun startEngagement()  {
		if (!publishState(ProximityVerifierState.PreparingEngagement)) {
			return
		}

		// Connection checks follow the profile's current bundle after recreation; MDL's bundle is unchanged.
		if (activeSession.transportProtocol.isConnected) {
			publishState(ProximityVerifierState.Error(ProximityError.InvalidState("Verifier is already connected")))
			return
		}

		// Fresh engagement keys imply a new Origin. Rebuild everything together, only for this profile.
		if (protocol == ProximityProtocol.OPENID4VP_OVER_ISO && sessionNeedsRecreation) {
			val createSession = reverseSessionFactory ?: run {
				publishState(ProximityVerifierState.Error(ProximityError.InvalidState("No reverse OPENID4VP_OVER_ISO session factory")))
				return
			}
			activeSession = createSession()
			sessionCipher = null
			activeSession.transportProtocol.setListener(transportListener)
			sessionNeedsRecreation = false
		}
		Logger(TAG).debug("startEngagement: protocol=$protocol")
		operationScope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL, ProximityProtocol.OPENID4VP, ProximityProtocol.OPENID4VP_OVER_ISO -> {
					if (protocol == ProximityProtocol.MDL) {
						val psm = (transportProtocol as? MdlTransportProtocol)?.prepareL2capPsm()
						(engagementBuilder as? MdlEngagementBuilder)?.l2capPsm = psm
					}
					transportProtocol.connect()
					val qrCodeData = engagementBuilder!!.createQrCodeForEngagement()
					val l2capPsm = (engagementBuilder as? MdlEngagementBuilder)?.l2capPsm
					Logger(TAG).debug("startEngagement: QR ready, qrChars=${qrCodeData.length} l2capPsm=${l2capPsm ?: "none"}")
					publishState(ProximityVerifierState.ReadyForEngagement(qrCodeData))
				}
			}
		}
	}

	fun disconnect() {
		Logger(TAG).debug("disconnect() was called")
		cancelPendingOperations()
		// Tear down the profile's current transport, including a replacement created after reset.
		activeSession.transportProtocol.disconnect()
		publishState(ProximityVerifierState.Disconnected)
	}

	fun reset() {
		Logger(TAG).debug("reset() was called")
		disconnect()
		// Profile freshness must not silently change MDL's existing reset semantics.
		if (protocol == ProximityProtocol.OPENID4VP_OVER_ISO) sessionNeedsRecreation = true
		verifierStateMutable.update { ProximityVerifierState.Initial }
	}

	fun connect() {
		if (!publishState(ProximityVerifierState.Connecting)) {
			return
		}
		Logger(TAG).debug("connect: starting transport")
		operationScope.launch(Dispatchers.IO) {
			// Resolve the current profile transport; no duplicated BLE implementation is necessary.
			activeSession.transportProtocol.connect()
		}

	}

	private fun processMessageReceived(message: ByteArray) {
		if (verifierStateMutable.value.isTerminal()) {
			return
		}
		operationScope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL, ProximityProtocol.OPENID4VP_OVER_ISO -> {
					// Reuse ISO framing/decryption while selecting application-profile rules separately from MDL.
					Logger(TAG).debug("Processing message of size ${message.size}")
					logPayloadDebug("Verifier received MDL payload", message)
					// if we don't yet have a session cipher, but we received a message, we are
					// probably in the reverse engagement flow, so try parse a DeviceEngagement
					if(sessionCipher == null) {
						val engagementData = (if (protocol == ProximityProtocol.OPENID4VP_OVER_ISO) {
							// Strict reverse-engagement requirements belong here, not in the generic MDL parser.
							TODO("Showcase omission: strict reverse Holder engagement parser")
						} else MdlEngagement.fromCbor(message)) ?: run {
							Logger(TAG).debug("First data package needs to be MdlEngagement for reverse engagement")
							disconnect()
							return@launch
						}
						val encodedReaderKey = if (protocol == ProximityProtocol.OPENID4VP_OVER_ISO) {
							// Match the profile's engagement key bytes for transcript/KDF binding; retain MDL's else branch.
							activeSession.readerKey?.let { encodeCborCanonical(it) } ?: return@launch
						} else encodeCbor(readerKey.toCbor())
						// Pair received Holder bytes with this profile session's key and transport, never an old bundle.
						sessionCipher = (activeSession.transportProtocol as MdlTransportProtocolExtensions).getSessionCipher(
							engagementData.originalData,
							encodedReaderKey,
							engagementData.coseKey,
						)
						if (sessionCipher == null) {
							Logger(TAG).error("Failed to derive session cipher from reverse engagement")
							publishState(
								ProximityVerifierState.Error(
									ProximityError.InvalidData("Failed to derive session cipher from received engagement")
								)
							)
							disconnect()
							return@launch
						}
						requestDocument()
						return@launch
					}
					val sessionData = MdlSessionData.fromCbor(message) ?: run {
						Logger(TAG).debug("Unable to create MdlSessionData")
						disconnect()
						return@launch
					}
					if (sessionData.status != null) {
						val reason = TerminationReason.fromCode(sessionData.status)
						Logger(TAG).debug("processMessageReceived status=${sessionData.status} reson: $reason, disconnecting, sessionData=$sessionData")
						publishState(ProximityVerifierState.Terminated(reason))
						disconnect()
						return@launch
					}
					val encryptedPayload = sessionData.data ?: run {
						Logger(TAG).debug("processMessageReceived data is null, disconnecting")
						publishState(ProximityVerifierState.Error(ProximityError.InvalidData("Received empty session data")))
						disconnect()
						return@launch
					}
					Logger(TAG).debug("decrypt started: encryptedBytes=${encryptedPayload.size}")
					when (val result = ProximityMdlUtils.decryptAndValidatePayload(
						encryptedPayload,
						sessionData.shaSum,
						sessionCipher,
					)) {
						is ProximityMdlUtils.PayloadDecryptResult.Success -> {
							val data = result.data
							Logger(TAG).debug("decrypt done: plaintextBytes=${data.size}")
							if(isDcApi){
								// data should be the dcql response
								Logger(TAG).debug("verification started: dcApi=true")
								val response = documentRequester.verifySubmittedDocuments(data)
								Logger(TAG).debug("verification done")
								publishState(ProximityVerifierState.VerificationResult(response))
							} else {
								// handle mdl device response
								publishState(ProximityVerifierState.Error(ProximityError.InvalidState("mdl not yet implemented")))
							}
						}
						is ProximityMdlUtils.PayloadDecryptResult.Failure -> {
							Logger(TAG).debug("processMessageReceived ${result.debugMessage}, disconnecting")
							val errorMessage = when (result.type) {
								ProximityMdlUtils.PayloadDecryptFailureType.SHA_MISMATCH -> "MDL payload hash mismatch"
								ProximityMdlUtils.PayloadDecryptFailureType.MISSING_CIPHER -> "Missing session cipher"
								ProximityMdlUtils.PayloadDecryptFailureType.DECRYPT_FAILED -> "Failed to decrypt session data"
							}
							publishState(ProximityVerifierState.Error(ProximityError.InvalidData(errorMessage)))
							disconnect()
							return@launch
						}
					}
				}
				ProximityProtocol.OPENID4VP -> {
					when (val current = verifierStateMutable.value) {
						is ProximityVerifierState.Connected -> publishState(ProximityVerifierState.AwaitingDocuments)
						is ProximityVerifierState.AwaitingDocuments -> {
							Logger(TAG).debug("verification started: protocol=OPENID4VP bytes=${message.size}")
							val verificationResult = documentRequester.verifySubmittedDocuments(message)
							Logger(TAG).debug("verification done")
							publishState(ProximityVerifierState.VerificationResult(verificationResult))
						}
						else -> publishState(
							ProximityVerifierState.Error(
								ProximityError.InvalidState("Received message in unexpected state: $current")
							)
						)
					}
				}
			}
		}
	}

	private fun cancelPendingOperations() {
		operationJob.cancelChildren()
	}

	private fun publishState(nextState: ProximityVerifierState): Boolean {
		while (true) {
			val currentState = verifierStateMutable.value
			if (currentState.isTerminal()) {
				return false
			}
			if (verifierStateMutable.compareAndSet(currentState, nextState)) {
				return true
			}
		}
	}

	private fun ProximityVerifierState.isTerminal(): Boolean =
		this is ProximityVerifierState.Terminated ||
			this is ProximityVerifierState.Disconnected ||
			this is ProximityVerifierState.Error ||
			this is ProximityVerifierState.VerificationResult<*>

}

// A deep shared ISO session bundle supports profile-only recreation without duplicating the transport stack.
internal data class VerifierSession(
	val readerKey: Value?,
	val engagementBuilder: EngagementBuilder?,
	val transportProtocol: TransportProtocol,
)

// Legacy Mdl* naming is reused as ISO transport/session machinery; this is NOT a native mDL flow.
// This factory is the place to express profile setup without modifying the existing MDL factory.
internal fun createReverseOpenId4VpOverIsoSession(
	verifierName: String,
	serviceUuid: Uuid,
	bleOptions: ProximityBleOptions,
): VerifierSession {
	TODO("Showcase omission: concrete reverse session factory")
}
