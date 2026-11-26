/* Copyright 2025 Ubique Innovation AG

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

package org.kapunsdk

import org.kapunsdk.credentials.SdJwt
import org.kapunsdk.credentials.registerInvalidAndUndisclosableClaims
import org.kapunsdk.credentials.toClaimsPointer
import uniffi.kapun_credential_core_rust.SignatureCreator
import uniffi.kapun_dcql_sdjwt_rust.SdJwtDecodeException
import uniffi.kapun_util_rust.Value
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SignatureCreatorBridgeTest {
    private val testSigner =
        object : SignatureCreator {
            override fun alg(): String = "ES256"

            override fun sign(bytes: ByteArray): ByteArray = byteArrayOf(1, 2, 3)
        }

    private fun issueSdJwt(claimName: String): String {
        val claims =
            Value.Object(
                mapOf(
                    "vct" to Value.String("test-type"),
                    claimName to Value.String("test-value"),
                ),
            )
        val credential =
            SdJwt.create(
                claims = claims,
                disclosures = listOf(listOf(claimName).toClaimsPointer()!!),
                keyId = "test-key",
                key = testSigner,
                pubKeyJwk = null,
            )
        return assertNotNull(credential).innerJwt.originalSdjwt
    }

    private fun assertInvalidDisclosure(jwt: String) {
        val failure =
            assertFailsWith<Throwable> {
                SdJwt.parse(jwt)
            }
        assertTrue(failure is SdJwtDecodeException.InvalidDisclosure)
    }

    @Test
    fun signerCallbackIsRegisteredWithTheSdJwtLibrary() {
        var signedPayload: ByteArray? = null
        val signer =
            object : SignatureCreator {
                override fun alg(): String = "ES256"

                override fun sign(bytes: ByteArray): ByteArray {
                    signedPayload = bytes
                    return byteArrayOf(1, 2, 3)
                }
            }

        val credential =
            assertNotNull(
                SdJwt.create(
                    claims = Value.Object(mapOf("vct" to Value.String("test-type"))),
                    disclosures = emptyList(),
                    keyId = "test-key",
                    key = signer,
                    pubKeyJwk = Value.Object(emptyMap()),
                ),
            )
        val presentation =
            credential
                .presentation()
                .apply {
                    withNonce("nonce")
                    withAudience("audience")
                }.build(signer.asNativeSdJwtSignatureCreator())

        assertTrue(presentation.endsWith(".AQID"))
        assertTrue(assertNotNull(signedPayload).isNotEmpty())
    }

    @Test
    fun registeredClaimListsAllowAndRejectExpectedClaims() {
        registerInvalidAndUndisclosableClaims(emptyList(), emptyList())
        try {
            val undisclosableJwt = issueSdJwt("custom_secret")
            val ordinaryJwt = issueSdJwt("ordinary_claim")
            val illegalJwt = issueSdJwt("reserved_custom_claim")

            assertEquals(1, SdJwt.parse(undisclosableJwt).getNumDisclosed())
            assertEquals(1, SdJwt.parse(ordinaryJwt).getNumDisclosed())
            assertEquals(1, SdJwt.parse(illegalJwt).getNumDisclosed())

            registerInvalidAndUndisclosableClaims(emptyList(), listOf("custom_secret"))
            assertInvalidDisclosure(undisclosableJwt)
            assertEquals(1, SdJwt.parse(ordinaryJwt).getNumDisclosed())

            registerInvalidAndUndisclosableClaims(listOf("reserved_custom_claim"), emptyList())
            assertInvalidDisclosure(illegalJwt)
            assertEquals(1, SdJwt.parse(undisclosableJwt).getNumDisclosed())

            registerInvalidAndUndisclosableClaims(emptyList(), emptyList())
            assertEquals(1, SdJwt.parse(undisclosableJwt).getNumDisclosed())
            assertEquals(1, SdJwt.parse(illegalJwt).getNumDisclosed())
        } finally {
            registerInvalidAndUndisclosableClaims(emptyList(), emptyList())
        }
    }
}
