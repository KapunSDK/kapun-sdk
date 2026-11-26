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
package org.kapunsdk.proximity.wallet

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.kapunsdk.proximity.ProximityError
import org.kapunsdk.proximity.ProximityProcessEvent
import org.kapunsdk.proximity.ProximityProtocol
import org.kapunsdk.proximity.documents.DocumentRequest
import org.kapunsdk.proximity.protocol.EngagementBuilder
import org.kapunsdk.proximity.protocol.TransportProtocol
import org.kapunsdk.proximity.protocol.mdl.MdlCoseKey
import org.kapunsdk.proximity.protocol.mdl.MdlEngagement
import org.kapunsdk.proximity.protocol.mdl.MdlEngagementBuilder
import org.kapunsdk.proximity.protocol.mdl.MdlSessionData
import org.kapunsdk.proximity.protocol.mdl.MdlSessionEstablishment
import org.kapunsdk.proximity.protocol.mdl.MdlTransportProtocol
import org.kapunsdk.proximity.protocol.mdl.MdlTransportProtocolExtensions
import org.kapunsdk.proximity.protocol.openid4vp.OpenId4VpTransportProtocol
import org.kapunsdk.proximity.util.ProximityMdlUtils
import org.kapunsdk.proximity.util.logPayloadDebug
import org.kapunsdk.proximity.verifier.TerminationReason
import org.kapunsdk.util.extensions.asArray
import org.kapunsdk.util.extensions.asBoolean
import org.kapunsdk.util.extensions.asBytes
import org.kapunsdk.util.extensions.asOrderedObject
import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.asTag
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.toCbor
import org.kapunsdk.util.log.Logger
import uniffi.kapun_crypto_rust.EphemeralKey
import uniffi.kapun_crypto_rust.KeyType
import uniffi.kapun_crypto_rust.Role
import uniffi.kapun_crypto_rust.SessionCipher
import uniffi.kapun_crypto_rust.sha256Rs
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.decodeCbor
import uniffi.kapun_util_rust.encodeCbor
import kotlin.uuid.Uuid

class ProximityWallet private constructor(
    private val protocol: ProximityProtocol,
    private val scope: CoroutineScope,
    private val engagementBuilder: EngagementBuilder?,
    private val transportProtocol: TransportProtocol,
    private var sessionCipher: SessionCipher? = null,
    var isDcApi: Boolean = false,
    var isReverse: Boolean = false,
    /** Stable identifier for this created wallet process. */
    val processId: Uuid = Uuid.random(),
) {
    companion object {
        private const val TAG = "ProximityWallet"
        private const val L2CAP_COMPLETION_CLEANUP_DELAY_MS = 1_000L

        fun createReverse(
            protocol: ProximityProtocol,
            scope: CoroutineScope,
            readerEngagement: String,
            keyType: KeyType = KeyType.ED25519,
            enableL2cap: Boolean = true,
        ): ProximityWallet =
            when (protocol) {
                ProximityProtocol.MDL -> {
                    val keypair = EphemeralKey(Role.SK_DEVICE, keyType)
                    val coseKey = MdlCoseKey.encodedFromPublicKeyBytes(keypair.publicKey(), keyType)
                    val readerEngagement = MdlEngagement.fromQrCode(readerEngagement)

                    val transportProtocol =
                        MdlTransportProtocol(
                            TransportProtocol.Role.WALLET,
                            readerEngagement?.centralClientUuid,
                            readerEngagement?.peripheralServerUuid,
                            keypair,
                            l2capPsm = readerEngagement?.l2capPsm,
                            enableL2cap = enableL2cap,
                            isEngagementPresenter = false,
                        )
                    val engagementBuilder =
                        MdlEngagementBuilder(
                            "",
                            coseKey,
                            null,
                            null,
                            false,
                            transportProtocol.peripheralServerModeTransportProtocol != null,
                            capabilities = ProximityMdlUtils.defaultDcApiCapabilities(),
                        )
                    // derive session key
                    val eReaderKey = readerEngagement!!.coseKey
                    val sessionCipher =
                        (transportProtocol as MdlTransportProtocolExtensions).getSessionCipher(
                            engagementBuilder.getEngagementBytes(),
                            eReaderKey,
                        )

                    ProximityWallet(
                        protocol,
                        scope,
                        engagementBuilder,
                        transportProtocol,
                        sessionCipher,
                        isReverse = true,
                    )
                }

                ProximityProtocol.OPENID4VP -> {
                    throw NotImplementedError("Openid4VP cannot use reverse iso engagement")
                }
            }

        fun create(
            protocol: ProximityProtocol,
            scope: CoroutineScope,
            serviceUuid: String,
            peripheralServerUuid: String? = null,
            keyType: KeyType = KeyType.ED25519,
            enableL2cap: Boolean = true,
        ): ProximityWallet =
            when (protocol) {
                ProximityProtocol.MDL -> {
                    val keypair = EphemeralKey(Role.SK_DEVICE, keyType)
                    val coseKey = MdlCoseKey.encodedFromPublicKeyBytes(keypair.publicKey(), keyType)

                    val transportProtocol =
                        MdlTransportProtocol(
                            TransportProtocol.Role.WALLET,
                            Uuid.parse(serviceUuid),
                            Uuid.parse(peripheralServerUuid!!),
                            keypair,
                            enableL2cap = enableL2cap,
                            isEngagementPresenter = true,
                        )
                    val engagementBuilder =
                        MdlEngagementBuilder(
                            "",
                            coseKey,
                            Uuid.parse(serviceUuid),
                            Uuid.parse(peripheralServerUuid!!),
                            false,
                            transportProtocol.peripheralServerModeTransportProtocol != null,
                            capabilities = ProximityMdlUtils.defaultDcApiCapabilities(),
                        )
                    ProximityWallet(protocol, scope, engagementBuilder, transportProtocol)
                }

                ProximityProtocol.OPENID4VP -> {
                    val transportProtocol =
                        OpenId4VpTransportProtocol(
                            TransportProtocol.Role.WALLET,
                            Uuid.parse(serviceUuid),
                        )
                    ProximityWallet(protocol, scope, null, transportProtocol)
                }
            }

        fun create(
            protocol: ProximityProtocol,
            scope: CoroutineScope,
            serviceUuid: Uuid,
            peripheralServerUuid: Uuid? = null,
            keyType: KeyType = KeyType.ED25519,
            enableL2cap: Boolean = true,
        ): ProximityWallet =
            when (protocol) {
                ProximityProtocol.MDL -> {
                    val keypair = EphemeralKey(Role.SK_DEVICE, keyType)
                    val coseKey = MdlCoseKey.encodedFromPublicKeyBytes(keypair.publicKey(), keyType)

                    val transportProtocol =
                        MdlTransportProtocol(
                            TransportProtocol.Role.WALLET,
                            serviceUuid,
                            peripheralServerUuid!!,
                            keypair,
                            enableL2cap = enableL2cap,
                            isEngagementPresenter = true,
                        )
                    // TODO: we probably should expose the lis of capabilities somehow to the constructor, or at least let the constructor
                    // choose, which protocols we wish to support.
                    val engagementBuilder =
                        MdlEngagementBuilder(
                            "",
                            coseKey,
                            serviceUuid,
                            peripheralServerUuid!!,
                            transportProtocol.centralClientModeTransportProtocol != null,
                            transportProtocol.peripheralServerModeTransportProtocol != null,
                            capabilities = ProximityMdlUtils.defaultDcApiCapabilities(),
                        )
                    ProximityWallet(protocol, scope, engagementBuilder, transportProtocol)
                }

                ProximityProtocol.OPENID4VP -> {
                    val transportProtocol =
                        OpenId4VpTransportProtocol(
                            TransportProtocol.Role.WALLET,
                            serviceUuid,
                        )
                    ProximityWallet(protocol, scope, null, transportProtocol)
                }
            }
    }

    private val walletStateMutable = MutableStateFlow<ProximityWalletState>(ProximityWalletState.Initial)
    val walletState = walletStateMutable.asStateFlow()

    /** Wallet state events tagged with [processId]. */
    val events = walletStateMutable.map { state -> ProximityProcessEvent(processId, state) }

    private var verifierName: String? = null

    private var deviceEngagementSent = false
    private var l2capCleanupJob: Job? = null
    private var l2capTerminationSent = false

    init {
        transportProtocol.setListener(
            object : TransportProtocol.Listener {
                override fun onConnecting() {
                    walletStateMutable.update { ProximityWalletState.Connecting(verifierName ?: "Unknown verifier") }
                }

                override fun onConnected() {
                    walletStateMutable.update { ProximityWalletState.Connected(verifierName ?: "Unknown verifier") }
                    this@ProximityWallet.scope.launch {
                        if (protocol == ProximityProtocol.MDL) {
                            if (isReverse && !deviceEngagementSent) {
                                sendDeviceEngagement()
                                deviceEngagementSent = true
                            }
                        }
                    }
                }

                override fun onDisconnected() {
                    if (walletStateMutable.value !is ProximityWalletState.Error &&
                        walletStateMutable.value !is ProximityWalletState.PresentationCompleted &&
                        !markSubmissionCompleted()
                    ) {
                        walletStateMutable.update { ProximityWalletState.Disconnected }
                    }
                }

                override fun onMessageReceived() {
                    val message = transportProtocol.getMessage()
                    if (message != null) {
                        processMessageReceived(message)
                    } else {
                        walletStateMutable.update {
                            ProximityWalletState.Error(ProximityError.InvalidData("Received message is null"))
                        }
                    }
                }

                override fun onTransportSpecificSessionTermination() {
                    disconnect()
                }

                override fun onError(error: ProximityError) {
                    walletStateMutable.update { ProximityWalletState.Error(error) }
                }
            },
        )
    }

    fun getSessionTranscript(): Value? = (transportProtocol as MdlTransportProtocolExtensions).sessionTranscript

    fun startEngagement(verifierName: String) {
        this.verifierName = verifierName

        Logger(TAG).debug("startEngagement: protocol=$protocol reverse=$isReverse")
        scope.launch(Dispatchers.IO) {
            when (protocol) {
                ProximityProtocol.MDL -> {
                    if (!this@ProximityWallet.isReverse) {
                        val psm = (transportProtocol as? MdlTransportProtocol)?.prepareL2capPsm()
                        (engagementBuilder as? MdlEngagementBuilder)?.l2capPsm = psm
                        val qrCodeData = engagementBuilder!!.createQrCodeForEngagement()
                        Logger(
                            TAG,
                        ).debug("startEngagement: QR ready, qrChars=${qrCodeData.length} l2capPsm=${psm ?: "none"}")
                        walletStateMutable.update {
                            ProximityWalletState.ReadyForEngagement(qrCodeData)
                        }
                    } else {
                        walletStateMutable.update {
                            ProximityWalletState.Connecting(verifierName)
                        }
                    }
                    transportProtocol.connect()
                }

                ProximityProtocol.OPENID4VP -> {
                    transportProtocol.connect()
                }
            }
        }
    }

    fun sendDeviceEngagement(): Boolean {
        val engagementData = (engagementBuilder as MdlEngagementBuilder).getEngagementBytes()
        Logger(TAG).debug("sendDeviceEngagement started: bytes=${engagementData.size}")
        transportProtocol.sendMessage(engagementData) { sent, total ->
            Logger(TAG).debug("sendDeviceEngagement progress: sent=$sent total=$total")
        }

        return true
    }

    fun submitDocument(data: ByteArray) {
        when (val state = walletState.value) {
            is ProximityWalletState.RequestingDocuments -> {}

            is ProximityWalletState.Error -> {
                Logger(TAG).debug("submitDocument ignored: walletState=$state")
                return
            }

            else -> {
                Logger(TAG).debug("submitDocument ignored: walletState=$state")
                walletStateMutable.update {
                    ProximityWalletState.Error(
                        ProximityError.InvalidState("Unable to submit: wallet is not ready to submit documents"),
                    )
                }
                return
            }
        }
        Logger(TAG).debug("submitDocument started: payloadBytes=${data.size}")
        walletStateMutable.update { ProximityWalletState.SubmittingDocuments(progress = 0.0) }
        val encryptedData = sessionCipher!!.encrypt(data)!!
        Logger(TAG).debug("submitDocument encrypted: cipherBytes=${encryptedData.size}")
        val payloadShaSum = sha256Rs(encryptedData)
        val payload =
            encodeCbor(
                mapOf(
                    "data" to encryptedData,
                    "shaSum" to payloadShaSum,
                ).toCbor(),
            )
        logPayloadDebug("Wallet sending MDL payload", payload)
        runCatching {
            transportProtocol.sendMessage(payload) { sent, total ->
                val progress = if (total > 0) sent.toDouble() / total.toDouble() else null
                Logger(TAG).debug("submitDocument progress: sent=$sent total=$total progress=$progress")
                walletStateMutable.update { ProximityWalletState.SubmittingDocuments(progress = progress) }
                if (progress != null && progress >= 1.0) {
                    markSubmissionCompleted()
                    if (walletStateMutable.value is ProximityWalletState.PresentationCompleted) {
                        scheduleL2capCleanup()
                    }
                }
            }
        }.onFailure { error ->
            Logger(TAG).error("submitDocument send failed: ${error.message ?: error::class.simpleName}")
            val message = error.message ?: error::class.simpleName ?: "Unknown error"
            walletStateMutable.update { ProximityWalletState.Error(ProximityError.Unknown(message)) }
            if ((transportProtocol as? MdlTransportProtocol)?.hasUsedL2cap() == true) {
                disconnect()
            }
        }
    }

    fun declinePresentation(): Boolean {
        if (sessionCipher == null) {
            disconnect()
            return false
        }

        // Build SessionData with null payload and status=user declined
        val sessionData =
            encodeCbor(
                mapOf(
                    "data" to Value.Null,
                    "status" to TerminationReason.REQUEST_REJECTED.code,
                ).toCbor(),
            )

        // Transport layer handles fragmentation; payload is already CBOR encoded
        l2capTerminationSent = true
        transportProtocol.sendMessage(sessionData, null)

        walletStateMutable.update { ProximityWalletState.Disconnected }
        transportProtocol.disconnect()

        return true
    }

    fun disconnect() {
        l2capCleanupJob?.cancel()
        l2capCleanupJob = null
        val previousState = walletStateMutable.value
        sendL2capSessionTermination(previousState)
        transportProtocol.disconnect()
        if (previousState !is ProximityWalletState.Error &&
            !markSubmissionCompleted() &&
            walletStateMutable.value !is ProximityWalletState.PresentationCompleted
        ) {
            walletStateMutable.update { ProximityWalletState.Disconnected }
        }
    }

    private fun sendL2capSessionTermination(previousState: ProximityWalletState) {
        val mdlTransport = transportProtocol as? MdlTransportProtocol ?: return
        if (l2capTerminationSent || previousState is ProximityWalletState.Disconnected ||
            previousState is ProximityWalletState.Error ||
            previousState is ProximityWalletState.PresentationCompleted ||
            sessionCipher == null || !mdlTransport.hasUsedL2cap()
        ) {
            return
        }

        val termination =
            encodeCbor(
                mapOf(
                    "data" to Value.Null,
                    "status" to TerminationReason.GENERAL_ERROR.code,
                ).toCbor(),
            )
        runCatching {
            Logger(TAG).debug("Sending ISO session termination over active L2CAP before closing the channel")
            transportProtocol.sendMessage(termination, null)
            l2capTerminationSent = true
        }.onFailure { error ->
            Logger(TAG).warn("Unable to send ISO session termination before L2CAP close: ${error.message}")
        }
    }

    private fun scheduleL2capCleanup() {
        val mdlTransport = transportProtocol as? MdlTransportProtocol ?: return
        if (walletStateMutable.value !is ProximityWalletState.PresentationCompleted) return
        if (!mdlTransport.hasUsedL2cap()) return

        l2capCleanupJob?.cancel()
        Logger(TAG).debug(
            "L2CAP presentation sent; waiting ${L2CAP_COMPLETION_CLEANUP_DELAY_MS}ms for reader termination before closing channel",
        )
        l2capCleanupJob =
            scope.launch {
                delay(L2CAP_COMPLETION_CLEANUP_DELAY_MS)
                if (walletStateMutable.value is ProximityWalletState.PresentationCompleted &&
                    mdlTransport.hasUsedL2cap()
                ) {
                    Logger(
                        TAG,
                    ).debug(
                        "L2CAP reader did not terminate the channel; closing BLE transport after completion timeout",
                    )
                    disconnect()
                }
            }
    }

    private fun processMessageReceived(message: ByteArray) {
        scope.launch(Dispatchers.IO) {
            when (protocol) {
                ProximityProtocol.MDL -> {
                    if (sessionCipher == null) {
                        val sessionEstablishment =
                            MdlSessionEstablishment.fromCbor(message) ?: run {
                                transportProtocol.disconnect()
                                return@launch
                            }
                        val builder = engagementBuilder as MdlEngagementBuilder
                        val eReaderKey =
                            sessionEstablishment.eReaderKey
                                .asTag()
                                ?.value
                                ?.firstOrNull()
                                ?.asBytes() ?: run {
                                transportProtocol.disconnect()
                                return@launch
                            }
                        Logger(TAG).debug("session cipher derivation started")
                        sessionCipher =
                            (transportProtocol as MdlTransportProtocolExtensions).getSessionCipher(
                                builder.getEngagementBytes(),
                                eReaderKey,
                            )
                        Logger(TAG).debug("session cipher derived, decrypting request")
                        val result =
                            sessionCipher?.decrypt(sessionEstablishment.data) ?: run {
                                disconnect()
                                return@launch
                            }
                        Logger(TAG).debug("request decrypted: plaintextBytes=${result.size}")
                        // The reader selected dcAPI
                        if (sessionEstablishment.dcApiSelected == true) {
                            isDcApi = true
                            val sessionTranscript =
                                (transportProtocol as MdlTransportProtocolExtensions).sessionTranscript ?: run {
                                    Logger(
                                        TAG,
                                    ).error("Wallet has no session transcript after deriving the session cipher")
                                    walletStateMutable.update {
                                        ProximityWalletState.Error(
                                            ProximityError.InvalidData("Missing session transcript"),
                                        )
                                    }
                                    disconnect()
                                    return@launch
                                }
                            val origin = ProximityMdlUtils.buildIsoOriginFromSessionTranscript(sessionTranscript)
                            // TODO: handle multiple requests and such
                            // TODO: we should choose which protocols we support and wish (e.g .signed not signed)
                            val dcRequest = Json.decodeFromString<JsonObject>(result.decodeToString())
                            // we just use the first request
                            runCatching {
                                dcRequest["requests"]!!
                                    .jsonArray
                                    .getOrNull(
                                        0,
                                    )!!
                                    .jsonObject["data"]!!
                                    .jsonObject["request"]!!
                                    .jsonPrimitive.content
                            }.onFailure { error ->
                                walletStateMutable.update {
                                    ProximityWalletState.Error(
                                        ProximityError.Unknown(
                                            error.message ?: error::class.simpleName ?: "Unknown error",
                                        ),
                                    )
                                }
                            }.onSuccess { result ->
                                // Update our state to openid4vp document selection (and set the origin to the session transcript hash)
                                walletStateMutable.update {
                                    ProximityWalletState.RequestingDocuments(
                                        DocumentRequest.OpenId4Vp(result, origin = origin),
                                    )
                                }
                            }
                        } else {
                            val request = decodeCbor(result)
                            val docRequests =
                                request.get("docRequests").asArray()!!.map {
                                    val itemsRequestBytes =
                                        it
                                            .get("itemsRequest")
                                            .asTag()
                                            ?.value
                                            ?.firstOrNull()
                                            ?.asBytes()!!
                                    val itemsRequest = decodeCbor(itemsRequestBytes)
                                    val namespaces = itemsRequest.get("nameSpaces")
                                    val elements = mutableListOf<DocumentRequest.MdlDocumentItem>()
                                    for ((namespace, entries) in namespaces.asOrderedObject()!!.entries) {
                                        for ((name, intentToRetain) in entries.asOrderedObject()!!.entries) {
                                            elements.add(
                                                DocumentRequest.MdlDocumentItem(
                                                    namespace.asString()!!,
                                                    name.asString()!!,
                                                    intentToRetain.asBoolean()!!,
                                                ),
                                            )
                                        }
                                    }
                                    DocumentRequest.MdlDocument(
                                        itemsRequest.get("docType").asString()!!,
                                        elements,
                                    )
                                }
                            walletStateMutable.update {
                                ProximityWalletState.RequestingDocuments(DocumentRequest.Mdl(docRequests))
                            }
                        }
                    } else {
                        val sessionData =
                            MdlSessionData.fromCbor(message) ?: run {
                                Logger(
                                    TAG,
                                ).debug("Wallet failed to decode MdlSessionData from message of size ${message.size}")
                                disconnect()
                                return@launch
                            }
                        // if session data contains the dcApiSelected flag
                        // we set isDcApi to true.
                        sessionData.dcApiSelected?.let {
                            isDcApi = it
                        }
                        if (sessionData.status != null) {
                            Logger(TAG).debug("Wallet received terminal status=${sessionData.status}, disconnecting")
                            if (!markSubmissionCompleted() &&
                                walletStateMutable.value !is ProximityWalletState.PresentationCompleted
                            ) {
                                walletStateMutable.update { ProximityWalletState.Disconnected }
                            }
                            disconnect()
                            return@launch
                        }
                        val encryptedPayload =
                            sessionData.data ?: run {
                                Logger(TAG).debug("Wallet received session data without payload, disconnecting")
                                walletStateMutable.update {
                                    ProximityWalletState.Error(
                                        ProximityError.InvalidData("Received empty session data"),
                                    )
                                }
                                disconnect()
                                return@launch
                            }
                        val data =
                            when (
                                val result =
                                    ProximityMdlUtils.decryptAndValidatePayload(
                                        encryptedPayload,
                                        sessionData.shaSum,
                                        sessionCipher,
                                    )
                            ) {
                                is ProximityMdlUtils.PayloadDecryptResult.Success -> {
                                    result.data
                                }

                                is ProximityMdlUtils.PayloadDecryptResult.Failure -> {
                                    Logger(TAG).debug("Wallet received session data ${result.debugMessage}")
                                    val errorMessage =
                                        when (result.type) {
                                            ProximityMdlUtils.PayloadDecryptFailureType.SHA_MISMATCH -> {
                                                "MDL payload hash mismatch"
                                            }

                                            ProximityMdlUtils.PayloadDecryptFailureType.MISSING_CIPHER -> {
                                                "Missing session cipher"
                                            }

                                            ProximityMdlUtils.PayloadDecryptFailureType.DECRYPT_FAILED -> {
                                                "Failed to decrypt session data"
                                            }
                                        }
                                    walletStateMutable.update {
                                        ProximityWalletState.Error(
                                            ProximityError.InvalidData(errorMessage),
                                        )
                                    }
                                    disconnect()
                                    return@launch
                                }
                            }

                        if (isDcApi) {
                            isDcApi = true

                            val sessionTranscript =
                                (transportProtocol as MdlTransportProtocolExtensions).sessionTranscript ?: run {
                                    Logger(
                                        TAG,
                                    ).error("Wallet has no session transcript while processing the DC API request")
                                    walletStateMutable.update {
                                        ProximityWalletState.Error(
                                            ProximityError.InvalidData("Missing session transcript"),
                                        )
                                    }
                                    disconnect()
                                    return@launch
                                }
                            val origin = ProximityMdlUtils.buildIsoOriginFromSessionTranscript(sessionTranscript)
                            // TODO: handle multiple requests and such
                            // TODO: we should choose which protocols we support and wish (e.g .signed not signed)
                            val dcRequest = Json.decodeFromString<JsonObject>(data.decodeToString())
                            // we just use the first request
                            runCatching {
                                dcRequest["requests"]!!
                                    .jsonArray
                                    .getOrNull(
                                        0,
                                    )!!
                                    .jsonObject["data"]!!
                                    .jsonObject["request"]!!
                                    .jsonPrimitive.content
                            }.onFailure { error ->
                                walletStateMutable.update {
                                    ProximityWalletState.Error(
                                        ProximityError.Unknown(
                                            error.message ?: error::class.simpleName ?: "Unknown error",
                                        ),
                                    )
                                }
                            }.onSuccess { result ->
                                // Update our state to openid4vp document selection (and set the origin to the session transcript hash)
                                walletStateMutable.update {
                                    ProximityWalletState.RequestingDocuments(
                                        DocumentRequest.OpenId4Vp(result, origin = origin),
                                    )
                                }
                            }
                        } else {
                            val request = decodeCbor(data)
                            if (request.get("docRequests") != Value.Null) {
                                val docRequests =
                                    request.get("docRequests").asArray()!!.map {
                                        val itemsRequestBytes =
                                            it
                                                .get("itemsRequest")
                                                .asTag()
                                                ?.value
                                                ?.firstOrNull()
                                                ?.asBytes()!!
                                        val itemsRequest = decodeCbor(itemsRequestBytes)
                                        val namespaces = itemsRequest.get("nameSpaces")
                                        val elements = mutableListOf<DocumentRequest.MdlDocumentItem>()
                                        for ((namespace, entries) in namespaces.asOrderedObject()!!.entries) {
                                            for ((name, intentToRetain) in entries.asOrderedObject()!!.entries) {
                                                elements.add(
                                                    DocumentRequest.MdlDocumentItem(
                                                        namespace.asString()!!,
                                                        name.asString()!!,
                                                        intentToRetain.asBoolean()!!,
                                                    ),
                                                )
                                            }
                                        }
                                        DocumentRequest.MdlDocument(
                                            itemsRequest.get("docType").asString()!!,
                                            elements,
                                        )
                                    }
                                walletStateMutable.update {
                                    ProximityWalletState.RequestingDocuments(DocumentRequest.Mdl(docRequests))
                                }
                            }
                        }
                    }
                }

                ProximityProtocol.OPENID4VP -> {
                    walletStateMutable.update { current ->
                        when (current) {
                            is ProximityWalletState.Connected -> {
                                val request = message.decodeToString()
                                // TODO Should not be decoded like this.
                                val documentRequest = DocumentRequest.OpenId4Vp(request)
                                ProximityWalletState.RequestingDocuments(documentRequest)
                            }

                            is ProximityWalletState.SubmittingDocuments -> {
                                transportProtocol.disconnect()
                                ProximityWalletState.PresentationCompleted
                            }

                            else -> {
                                ProximityWalletState.Error(
                                    ProximityError.InvalidState("Received message in unexpected state: $current"),
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun markSubmissionCompleted(): Boolean =
        if (walletStateMutable.value is ProximityWalletState.SubmittingDocuments) {
            Logger(TAG).debug("markSubmissionCompleted: transitioning to PresentationCompleted")
            (transportProtocol as? MdlTransportProtocol)?.markSessionCompleted()
            walletStateMutable.update { ProximityWalletState.PresentationCompleted }
            true
        } else {
            false
        }
}
