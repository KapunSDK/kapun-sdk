/* Copyright 2026 Ubique Innovation AG

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

import org.kapunsdk.proximity.util.ProximityMdlUtils
import org.kapunsdk.util.extensions.toCbor
import org.kapunsdk.util.extensions.asOrderedObject
import uniffi.kapun_crypto_rust.EphemeralKey
import uniffi.kapun_crypto_rust.KeyType
import uniffi.kapun_crypto_rust.Role
import uniffi.kapun_crypto_rust.base64UrlEncode
import uniffi.kapun_crypto_rust.sha256Rs
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.JsonNumber
import uniffi.kapun_util_rust.decodeCbor
import uniffi.kapun_util_rust.encodeCbor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Executable, labelled vectors for the proximity appendix in the Typst documentation.
 *
 * The standard output is deliberately machine-readable enough to copy into a documentation
 * build step. Run with Gradle's standard streams enabled (the module config enables it by default):
 *
 *   ./gradlew :kapun-proximity:jvmTest --tests '*ProximityDocumentationVectorTest*'
 */
class ProximityDocumentationVectorTest {
    private val centralUuid = Uuid.parse("00000002-a123-48ce-896b-4c76973373e6")
    private val peripheralUuid = Uuid.parse("00000001-a123-48ce-896b-4c76973373e6")

    @Test
    fun documentation_reader_engagement_and_qr_round_trip() {
        val coseKey = MdlCoseKey.encodedFromPublicKeyBytes(
            p256PublicKey(),
            KeyType.P256,
        )
        val builder = MdlEngagementBuilder(
            verifierName = "Documentation reader",
            coseKey = coseKey,
            centralClientUuid = centralUuid,
            peripheralServerUuid = peripheralUuid,
            centralClientModeSupported = true,
            peripheralServerModeSupported = true,
            capabilities = MdlCapabilities(
                mapOf(
                    MdlCapabilities.DC_API_CAPABILITY_KEY to DcApiCapability(
                        listOf("openid4vp-v1-signed"),
                    ),
                ),
            ),
        )

        val engagementBytes = builder.getEngagementBytes()
        val qrCode = builder.createQrCodeForEngagement()
        val parsed = assertNotNull(MdlEngagement.fromQrCode(qrCode))

        assertTrue(qrCode.startsWith("mdoc:"))
        assertContentEquals(engagementBytes, parsed.originalData)
        assertEquals(centralUuid, parsed.centralClientUuid)
        assertEquals(peripheralUuid, parsed.peripheralServerUuid)
        assertTrue(parsed.centralClientModeSupported)
        assertTrue(parsed.peripheralServerModeSupported)
        assertNotNull(parsed.capabilities)
        // Map insertion order is not canonicalized by the SDK, so the re-encoded bytes need not
        // be byte-identical. The UUID, mode flags, key and capabilities above are the semantic
        // round-trip assertions.
        assertTrue(parsed.getEngagementBytes().isNotEmpty())

        printPayload("Reader Engagement", engagementBytes)
        println("PROXIMITY_DOC[Reader Engagement].qr=$qrCode")

        val deviceEngagementBytes = MdlEngagementBuilder(
            verifierName = "Documentation wallet",
            coseKey = MdlCoseKey.encodedFromPublicKeyBytes(
                p256PublicKey(2),
                KeyType.P256,
            ),
            centralClientUuid = null,
            peripheralServerUuid = null,
            centralClientModeSupported = false,
            peripheralServerModeSupported = false,
            capabilities = builderCapabilities(),
        ).getEngagementBytes()
        val parsedDevice = assertNotNull(MdlEngagement.fromCbor(deviceEngagementBytes))
        assertFalse(parsedDevice.centralClientModeSupported)
        assertFalse(parsedDevice.peripheralServerModeSupported)
        assertTransferMethodsAbsent(deviceEngagementBytes)
        printPayload("Device Engagement (Normal Flow)", deviceEngagementBytes)
        println("PROXIMITY_DOC[Device Engagement (sent back)].transfer_methods_present=false")
    }

    @Test
    fun documentation_encoded_request_response_and_encryption_round_trip() {
        val readerKey = EphemeralKey(Role.SK_READER, KeyType.P256)
        val deviceKey = EphemeralKey(Role.SK_DEVICE, KeyType.P256)
        val readerEngagementBytes = MdlEngagementBuilder(
            verifierName = "Documentation reader",
            coseKey = MdlCoseKey.encodedFromPublicKeyBytes(readerKey.publicKey(), KeyType.P256),
            centralClientUuid = centralUuid,
            peripheralServerUuid = null,
            centralClientModeSupported = true,
            peripheralServerModeSupported = false,
        ).getEngagementBytes()
        val deviceEngagementBytes = MdlEngagementBuilder(
            verifierName = "Documentation wallet",
            coseKey = MdlCoseKey.encodedFromPublicKeyBytes(deviceKey.publicKey(), KeyType.P256),
            centralClientUuid = null,
            peripheralServerUuid = peripheralUuid,
            centralClientModeSupported = false,
            peripheralServerModeSupported = true,
        ).getEngagementBytes()
        val eReaderKeyBytes = encodeCbor(
            MdlCoseKey.fromPublicKeyBytes(readerKey.publicKey(), KeyType.P256),
        )

        // ISO 18013-5 SessionTranscript and the tagged bytes used as the HKDF input.
        val sessionTranscript = listOf(
            24 to deviceEngagementBytes,
            24 to eReaderKeyBytes,
            Value.Null,
        ).toCbor()
        val sessionTranscriptBytes = encodeCbor(
            (24 to encodeCbor(sessionTranscript)).toCbor(),
        )
        val origin = ProximityMdlUtils.buildIsoOriginFromSessionTranscript(sessionTranscript)
        assertTrue(origin.startsWith("iso-18013-5://"))

        val readerCipher = assertNotNull(
            readerKey.getSessionCipher(sessionTranscriptBytes, deviceKey.publicKey()),
        )
        val deviceCipher = assertNotNull(
            deviceKey.getSessionCipher(sessionTranscriptBytes, readerKey.publicKey()),
        )

        val requestPlaintext = """
            {"requests":[{"protocol":"openid4vp-v1-signed","data":{"request":"eyJhbGciOiJFUzI1NiJ9.docs-example"}}]}
        """.trimIndent().encodeToByteArray()
        val encryptedRequest = assertNotNull(readerCipher.encrypt(requestPlaintext))
        val establishment = MdlSessionEstablishment(
            eReaderKey = (24 to encodeCbor(MdlCoseKey.fromPublicKeyBytes(readerKey.publicKey(), KeyType.P256))).toCbor(),
            data = encryptedRequest,
            dcApiSelected = true,
        )
        val encodedRequest = establishment.asCbor()
        val decodedEstablishment = assertNotNull(MdlSessionEstablishment.fromCbor(encodedRequest))
        assertContentEquals(encryptedRequest, decodedEstablishment.data)
        assertTrue(decodedEstablishment.dcApiSelected == true)
        assertContentEquals(requestPlaintext, assertNotNull(deviceCipher.decrypt(encryptedRequest)))

        val responsePlaintext = """{"vp_token":["example-sd-jwt"]}""".encodeToByteArray()
        val encryptedResponse = assertNotNull(deviceCipher.encrypt(responsePlaintext))
        val response = MdlSessionData(
            data = encryptedResponse,
            status = null,
            shaSum = sha256Rs(encryptedResponse),
            dcApiSelected = true,
        )
        val encodedResponse = response.asCbor()
        val decodedResponse = assertNotNull(MdlSessionData.fromCbor(encodedResponse))
        assertContentEquals(encryptedResponse, decodedResponse.data)
        assertContentEquals(responsePlaintext, assertNotNull(readerCipher.decrypt(encryptedResponse)))

        printPayload("Reader Engagement", readerEngagementBytes)
        printPayload("Device Engagement (sent back)", deviceEngagementBytes)
        printPayload("Encoded Document-Request", encodedRequest)
        printPayload("Encoded Document-Response", encodedResponse)
        printPayload("Encrypted Request", encryptedRequest)
        printPayload("Encrypted Response", encryptedResponse)
        println("PROXIMITY_DOC[Encryption].reader_public_key_sec1_hex=${readerKey.publicKey().toHex()}")
        println("PROXIMITY_DOC[Encryption].device_public_key_sec1_hex=${deviceKey.publicKey().toHex()}")
        println("PROXIMITY_DOC[Encryption].session_transcript_outer_hex=${sessionTranscriptBytes.toHex()}")
        println("PROXIMITY_DOC[Encryption].origin=$origin")
        println("PROXIMITY_DOC[Encryption].plaintext_request=${requestPlaintext.decodeToString()}")
        println("PROXIMITY_DOC[Encryption].plaintext_response=${responsePlaintext.decodeToString()}")
        println("PROXIMITY_DOC[Encryption].decryption_verified=true")
    }

    @Test
    fun documentation_normal_and_reverse_flow_first_application_messages() {
        val normalReaderKey = EphemeralKey(Role.SK_READER, KeyType.P256)
        val normalDeviceKey = EphemeralKey(Role.SK_DEVICE, KeyType.P256)
        val normalDeviceEngagement = deviceEngagement(normalDeviceKey)
        val normalRequest = assertFlowRoundTrip(
            normalReaderKey,
            normalDeviceKey,
            normalDeviceEngagement,
        )
        val parsedNormalDevice = assertNotNull(MdlEngagement.fromCbor(normalDeviceEngagement))
        assertFalse(parsedNormalDevice.centralClientModeSupported)
        assertTrue(parsedNormalDevice.peripheralServerModeSupported)

        println("PROXIMITY_DOC[Normal Flow].scanned_qr_model=DeviceEngagement")
        printPayload("Normal Flow QR", normalDeviceEngagement)
        println("PROXIMITY_DOC[Normal Flow].first_application_message_model=SessionEstablishment")
        println("PROXIMITY_DOC[Normal Flow].round_trip_verified=true")
        printPayload("Normal Flow First Application Message", normalRequest)

        val reverseReaderKey = EphemeralKey(Role.SK_READER, KeyType.P256)
        val reverseDeviceKey = EphemeralKey(Role.SK_DEVICE, KeyType.P256)
        val reverseReaderEngagement = readerEngagement(reverseReaderKey)
        val reverseDeviceEngagement = reverseDeviceEngagement(reverseDeviceKey)
        val reverseRequest = assertFlowRoundTrip(
            reverseReaderKey,
            reverseDeviceKey,
            reverseDeviceEngagement,
        )
        val parsedReverseReader = assertNotNull(MdlEngagement.fromCbor(reverseReaderEngagement))
        val parsedReverseDevice = assertNotNull(MdlEngagement.fromCbor(reverseDeviceEngagement))
        assertTrue(parsedReverseReader.centralClientModeSupported)
        assertFalse(parsedReverseReader.peripheralServerModeSupported)
        assertFalse(parsedReverseDevice.centralClientModeSupported)
        assertFalse(parsedReverseDevice.peripheralServerModeSupported)
        assertTransferMethodsAbsent(reverseDeviceEngagement)

        println("PROXIMITY_DOC[Reverse Flow].scanned_qr_model=ReaderEngagement")
        printPayload("Reverse Flow QR", reverseReaderEngagement)
        println("PROXIMITY_DOC[Reverse Flow].first_application_message_model=DeviceEngagement")
        printPayload("Reverse Flow First Application Message", reverseDeviceEngagement)
        println("PROXIMITY_DOC[Reverse Flow].reader_next_message_model=SessionEstablishment")
        println("PROXIMITY_DOC[Reverse Flow].round_trip_verified=true")
        printPayload("Reverse Flow Second Application Message", reverseRequest)
    }

    /** Verifies payload -> AES-GCM -> CBOR -> CBOR decode -> AES-GCM decrypt -> payload bytes. */
    private fun assertFlowRoundTrip(
        readerKey: EphemeralKey,
        deviceKey: EphemeralKey,
        deviceEngagementBytes: ByteArray,
    ): ByteArray {
        val eReaderKey = MdlCoseKey.fromPublicKeyBytes(readerKey.publicKey(), KeyType.P256)
        val eReaderKeyBytes = encodeCbor(eReaderKey)
        val transcript = listOf(
            24 to deviceEngagementBytes,
            24 to eReaderKeyBytes,
            Value.Null,
        ).toCbor()
        val transcriptInput = encodeCbor((24 to encodeCbor(transcript)).toCbor())
        val readerCipher = assertNotNull(
            readerKey.getSessionCipher(transcriptInput, deviceKey.publicKey()),
        )
        val deviceCipher = assertNotNull(
            deviceKey.getSessionCipher(transcriptInput, readerKey.publicKey()),
        )

        val requestPlaintext =
            """{"requests":[{"protocol":"openid4vp-v1-signed","data":{"request":"doc-example"}}]}"""
                .encodeToByteArray()
        val encryptedRequest = assertNotNull(readerCipher.encrypt(requestPlaintext))
        val encodedRequest = MdlSessionEstablishment(
            eReaderKey = (24 to eReaderKeyBytes).toCbor(),
            data = encryptedRequest,
            dcApiSelected = true,
        ).asCbor()
        val decodedRequest = assertNotNull(MdlSessionEstablishment.fromCbor(encodedRequest))
        assertContentEquals(encryptedRequest, decodedRequest.data)
        assertContentEquals(requestPlaintext, assertNotNull(deviceCipher.decrypt(decodedRequest.data)))

        val responsePlaintext = """{"vp_token":["doc-example"]}""".encodeToByteArray()
        val encryptedResponse = assertNotNull(deviceCipher.encrypt(responsePlaintext))
        val encodedResponse = MdlSessionData(
            data = encryptedResponse,
            status = null,
            shaSum = sha256Rs(encryptedResponse),
            dcApiSelected = true,
        ).asCbor()
        val decodedResponse = assertNotNull(MdlSessionData.fromCbor(encodedResponse))
        val decodedResponseBytes = assertNotNull(decodedResponse.data)
        assertContentEquals(encryptedResponse, decodedResponseBytes)
        assertContentEquals(responsePlaintext, assertNotNull(readerCipher.decrypt(decodedResponseBytes)))
        assertContentEquals(sha256Rs(encryptedResponse), decodedResponse.shaSum)
        return encodedRequest
    }

    private fun readerEngagement(readerKey: EphemeralKey) = MdlEngagementBuilder(
        verifierName = "Documentation reader",
        coseKey = MdlCoseKey.encodedFromPublicKeyBytes(readerKey.publicKey(), KeyType.P256),
        centralClientUuid = centralUuid,
        peripheralServerUuid = null,
        centralClientModeSupported = true,
        peripheralServerModeSupported = false,
        capabilities = builderCapabilities(),
    ).getEngagementBytes()

    private fun deviceEngagement(deviceKey: EphemeralKey) = MdlEngagementBuilder(
        verifierName = "Documentation wallet",
        coseKey = MdlCoseKey.encodedFromPublicKeyBytes(deviceKey.publicKey(), KeyType.P256),
        centralClientUuid = null,
        peripheralServerUuid = peripheralUuid,
        centralClientModeSupported = false,
        peripheralServerModeSupported = true,
        capabilities = builderCapabilities(),
    ).getEngagementBytes()

    private fun reverseDeviceEngagement(deviceKey: EphemeralKey) = MdlEngagementBuilder(
        verifierName = "Documentation wallet reverse engagement",
        coseKey = MdlCoseKey.encodedFromPublicKeyBytes(deviceKey.publicKey(), KeyType.P256),
        centralClientUuid = null,
        peripheralServerUuid = null,
        centralClientModeSupported = false,
        peripheralServerModeSupported = false,
        capabilities = builderCapabilities(),
    ).getEngagementBytes()

    private fun assertTransferMethodsAbsent(engagementBytes: ByteArray) {
        val decoded = assertNotNull(decodeCbor(engagementBytes).asOrderedObject())
        assertFalse(decoded.entries.any { it.key == Value.Number(JsonNumber.Integer(2)) })
    }

    private fun builderCapabilities() = MdlCapabilities(
        mapOf(
            MdlCapabilities.DC_API_CAPABILITY_KEY to DcApiCapability(
                listOf("openid4vp-v1-signed"),
            ),
        ),
    )

    private fun p256PublicKey(offset: Int = 1): ByteArray =
        byteArrayOf(0x04) + ByteArray(64) { (it + offset).toByte() }

    private fun printPayload(label: String, bytes: ByteArray) {
        println("PROXIMITY_DOC[$label].cbor_hex=${bytes.toHex()}")
        println("PROXIMITY_DOC[$label].base64url=${base64UrlEncode(bytes)}")
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
