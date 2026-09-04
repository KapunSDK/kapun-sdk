/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

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
import kotlinx.coroutines.flow.update
import uniffi.kapun_crypto_rust.EphemeralKey
import uniffi.kapun_crypto_rust.KeyType
import uniffi.kapun_crypto_rust.Role
import uniffi.kapun_crypto_rust.SessionCipher
import uniffi.kapun_crypto_rust.base64UrlEncode
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.encodeCbor
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
	private val readerKey: Value? = null
) {
	private val operationJob = SupervisorJob(scope.coroutineContext[Job])
	private val operationScope = CoroutineScope(scope.coroutineContext + operationJob)

	companion object {
		fun <T> createReverse(protocol: ProximityProtocol,
							  scope: CoroutineScope,
							  verifierName: String,
							  requester: DocumentRequester<T>,
							  serviceUuid: String,
							  preferDcApi: Boolean = true,
							  peripheralServerUuid: String? = null,
							  keyType: KeyType = KeyType.ED25519): ProximityVerifier<T> {
			val publicKey = EphemeralKey(Role.SK_READER, keyType)
			return when (protocol) {
				ProximityProtocol.MDL -> {
					val coseKey = MdlCoseKey.fromPublicKeyBytes(publicKey.publicKey(), keyType)
					val coseKeyEncoded = encodeCbor(coseKey)

					val transportProtocol = MdlTransportProtocol(
						TransportProtocol.Role.VERIFIER,
						Uuid.parse(serviceUuid),
						peripheralServerUuid?.let { Uuid.parse(it)},
						publicKey
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
			keyType: KeyType = KeyType.ED25519
		): ProximityVerifier<T>? {
			val publicKey = EphemeralKey(Role.SK_READER, keyType)
			return when (protocol) {
				ProximityProtocol.MDL -> {
					val coseKey = MdlCoseKey.fromPublicKeyBytes(publicKey.publicKey(), keyType)
					val engagementData = qrcodeData ?: return null
					val deviceEngagement = MdlEngagement.fromQrCode(engagementData)
					val transportProtocol = MdlTransportProtocol(
						TransportProtocol.Role.VERIFIER,
						deviceEngagement?.centralClientUuid,
						deviceEngagement?.peripheralServerUuid,
						publicKey
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

					if(protocol == ProximityProtocol.MDL) {
						// We don't have a device engagement yet so wait for the first package
						// from the wallet
						when(engagementBuilder) {
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
					val message = transportProtocol.getMessage()
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
			}
		)
	}

	 fun requestDocument() {
		if (verifierStateMutable.value.isTerminal()) {
			return
		}
		operationScope.launch {
			// The session transcript is needed to derive origin
			val sessionTranscript = (transportProtocol as MdlTransportProtocolExtensions).sessionTranscript ?: run {
				publishState(ProximityVerifierState.Error(ProximityError.InvalidData("failed to get session transcript")))
				return@launch
			}
			val origin = ProximityMdlUtils.buildIsoOriginFromSessionTranscript(sessionTranscript)
			var documentRequest = documentRequester.createDocumentRequest(origin)
			when(documentRequest) {
				is DocumentRequest.Mdl -> {
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
					readerKey ?: run {
						publishState(ProximityVerifierState.Error(ProximityError.InvalidData("reader key is null")))
						return@launch
					}
					val encryptedData = currentCipher.encrypt(serializedDcRequest.encodeToByteArray()) ?: run {
						publishState(ProximityVerifierState.Error(ProximityError.InvalidData("failed to encrypt data")))
						return@launch
					}
					var readerKeyTagged = (24 to encodeCbor(readerKey.toCbor())).toCbor()
					// In the session establishment data package, we need to transmit the other part of the key (ours)
					var sessionEstablishment = MdlSessionEstablishment(readerKeyTagged, encryptedData, true)
					transportProtocol.sendMessage(sessionEstablishment.asCbor())
					publishState(ProximityVerifierState.AwaitingDocuments)
				}
			}

		}
	}

	@Throws(Exception::class)
	fun startEngagement()  {
		if (!publishState(ProximityVerifierState.PreparingEngagement)) {
			return
		}

		if (transportProtocol.isConnected) {
			publishState(ProximityVerifierState.Error(ProximityError.InvalidState("Verifier is already connected")))
			return
		}

		operationScope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL -> {
					transportProtocol.connect()
					val qrCodeData = engagementBuilder!!.createQrCodeForEngagement()
					publishState(ProximityVerifierState.ReadyForEngagement(qrCodeData))
				}
				ProximityProtocol.OPENID4VP -> {
					transportProtocol.connect()
					val qrCodeData = engagementBuilder!!.createQrCodeForEngagement()
					publishState(ProximityVerifierState.ReadyForEngagement(qrCodeData))
				}
			}
		}
	}

	fun disconnect() {
		Logger.debug("disconnect() was called")
		cancelPendingOperations()
		transportProtocol.disconnect()
		publishState(ProximityVerifierState.Disconnected)
	}

	fun reset() {
		Logger.debug("reset() was called")
		disconnect()
		verifierStateMutable.update { ProximityVerifierState.Initial }
	}

	fun connect() {
		if (!publishState(ProximityVerifierState.Connecting)) {
			return
		}
		operationScope.launch(Dispatchers.IO) {
			transportProtocol.connect()
		}

	}

	private fun processMessageReceived(message: ByteArray) {
		if (verifierStateMutable.value.isTerminal()) {
			return
		}
		operationScope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL -> {
					Logger.debug("Processing message of size ${message.size}")
					logPayloadDebug("Verifier received MDL payload", message)
					// if we don't yet have a session cipher, but we received a message, we are
					// probably in the reverse engagement flow, so try parse a DeviceEngagement
					if(sessionCipher == null) {
						val engagementData = MdlEngagement.fromCbor(message) ?: run {
							Logger.debug("First data package needs to be MdlEngagement for reverse engagement")
							disconnect()
							return@launch
						}
						sessionCipher = (transportProtocol as MdlTransportProtocolExtensions).getSessionCipher(engagementData.originalData, encodeCbor(readerKey.toCbor()), engagementData.coseKey)
						requestDocument()
						return@launch
					}
					val sessionData = MdlSessionData.fromCbor(message) ?: run {
						Logger.debug("Unable to create MdlSessionData")
						disconnect()
						return@launch
					}
					if (sessionData.status != null) {
						val reason = TerminationReason.fromCode(sessionData.status)
						Logger.debug("processMessageReceived status=${sessionData.status} reson: $reason, disconnecting, sessionData=$sessionData")
						publishState(ProximityVerifierState.Terminated(reason))
						disconnect()
						return@launch
					}
					val encryptedPayload = sessionData.data ?: run {
						Logger.debug("processMessageReceived data is null, disconnecting")
						publishState(ProximityVerifierState.Error(ProximityError.InvalidData("Received empty session data")))
						disconnect()
						return@launch
					}
					when (val result = ProximityMdlUtils.decryptAndValidatePayload(
						encryptedPayload,
						sessionData.shaSum,
						sessionCipher,
					)) {
						is ProximityMdlUtils.PayloadDecryptResult.Success -> {
							val data = result.data
							if(isDcApi){
								// data should be the dcql response
								val response = documentRequester.verifySubmittedDocuments(data)
								publishState(ProximityVerifierState.VerificationResult(response))
							} else {
								// handle mdl device response
								publishState(ProximityVerifierState.Error(ProximityError.InvalidState("mdl not yet implemented")))
							}
						}
						is ProximityMdlUtils.PayloadDecryptResult.Failure -> {
							Logger.debug("processMessageReceived ${result.debugMessage}, disconnecting")
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
							val verificationResult = documentRequester.verifySubmittedDocuments(message)
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
