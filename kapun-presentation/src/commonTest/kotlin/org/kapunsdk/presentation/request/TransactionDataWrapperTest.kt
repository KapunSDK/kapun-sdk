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

package org.kapunsdk.presentation.request

import org.kapunsdk.wallet.process.presentation.models.TransactionDataWrapper
import uniffi.kapun_credential_core_rust.SpecVersion
import uniffi.kapun_util_rust.Value
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

@OptIn(ExperimentalEncodingApi::class)
class TransactionDataWrapperTest {
    private fun transactionData(type: String): Value.String {
        val payload = """{"type":"$type","signatureQualifier":null,"credentialID":null,"documentDigests":null,"processID":null,"QC_terms_conditions_uri":null,"QC_hash":null,"QC_hashAlgorithmOID":null}"""
        return Value.String(Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(payload.encodeToByteArray()))
    }

    private fun descriptorData() = Value.Object(mapOf(
        "input_descriptors" to Value.Array(listOf(Value.Object(mapOf(
            "id" to Value.String("credential"),
            "transaction_data" to Value.Array(listOf(transactionData("nested"))),
        )))),
    ))

    @Test
    fun ignoresTransactionDataInsideInputDescriptors() {
        val request = Value.Object(mapOf("presentation_definition" to descriptorData()))
        assertNull(TransactionDataWrapper.fromValue(request))
    }

    @Test
    fun parsesTopLevelTransactionDataEvenWhenInputDescriptorsContainData() {
        val encoded = transactionData("qes_authorization")
        val request = Value.Object(mapOf(
            "presentation_definition" to descriptorData(),
            "transaction_data" to Value.Array(listOf(encoded)),
        ))
        val parsed = assertIs<TransactionDataWrapper.OpenId4Vp>(TransactionDataWrapper.fromValue(request))
        assertEquals("qes_authorization", parsed.value.single().second.type)
        assertEquals(encoded, Value.String(parsed.value.single().first))
        assertEquals(SpecVersion.OID4_VP_DRAFT23, parsed.specVersion())
        assertEquals(parsed.value, parsed.getForCredential("credential"))
    }
}
