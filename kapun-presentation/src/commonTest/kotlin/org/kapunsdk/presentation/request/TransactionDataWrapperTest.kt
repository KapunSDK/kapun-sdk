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
import org.kapunsdk.presentation.request.model.InvalidTransactionDataException
import org.kapunsdk.presentation.request.model.TransactionDataProfile
import org.kapunsdk.util.extensions.fromJsonElement
import kotlinx.serialization.json.*
import uniffi.kapun_util_rust.Value
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.*

@OptIn(ExperimentalEncodingApi::class)
class TransactionDataWrapperTest {
    private val type = "https://example.com/transaction"
    private val profiles = mapOf(type to TransactionDataProfile(setOf("amount")) { payload ->
        require((payload["amount"] as? JsonPrimitive)?.intOrNull?.let { it > 0 } == true)
    })

    private fun payload(ids: List<String> = listOf("first"), algorithms: JsonElement? = null) = buildJsonObject {
        put("type", type)
        put("credential_ids", JsonArray(ids.map(::JsonPrimitive)))
        put("amount", 10)
        if (algorithms != null) put("transaction_data_hashes_alg", algorithms)
    }

    private fun encode(payload: JsonElement): String =
        Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(payload.toString().encodeToByteArray())

    private fun request(entries: List<String>, query: String = """
        {"credentials":[{"id":"first","format":"dc+sd-jwt"},{"id":"second","format":"dc+sd-jwt"}]}
    """): Value = Value.fromJsonElement(buildJsonObject {
        put("dcql_query", Json.parseToJsonElement(query))
        put("transaction_data", JsonArray(entries.map(::JsonPrimitive)))
    })

    private fun parse(value: Value) = assertNotNull(TransactionDataWrapper.fromValue(value, profiles))

    // OpenID4VP 1.0 Final §5.1 (comments removed from the illustrative JSON).
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.1
    @Test
    fun parsesFinalSpecificationExampleWithAnExplicitProfile() {
        val encoded = "eyJ0eXBlIjoiZXhhbXBsZV90eXBlIiwiY3JlZGVudGlhbF9pZHMiOlsiaWRfY2FyZF9jcmVkZW50aWFsIl19"
        val request = request(listOf(encoded), """{"credentials":[{"id":"id_card_credential","format":"dc+sd-jwt"}]}""")
        val parsed = assertNotNull(TransactionDataWrapper.fromValue(request,
            mapOf("example_type" to TransactionDataProfile(emptySet()) {})))
        assertEquals(mapOf("id_card_credential" to listOf(encoded)),
            parsed.selectForCredentials(setOf("id_card_credential")))
    }

    @Test
    fun preservesEncodedInputAndSelectsExactlyOneEligibleCredential() {
        val first = encode(payload(listOf("first", "second")))
        val second = encode(payload(listOf("second")))
        val parsed = parse(request(listOf(first, second)))
        assertEquals(mapOf("first" to listOf(first), "second" to listOf(second)),
            parsed.selectForCredentials(setOf("first", "second")))
        assertEquals(mapOf("second" to listOf(first, second)), parsed.selectForCredentials(setOf("second")))
        assertFailsWith<InvalidTransactionDataException> { parsed.selectForCredentials(setOf("unrelated")) }
    }

    @Test
    fun allowsOneCredentialFromAQueryThatPermitsMultiple() {
        val encoded = encode(payload())
        val parsed = parse(request(listOf(encoded),
            """{"credentials":[{"id":"first","format":"dc+sd-jwt","multiple":true}]}"""))
        assertEquals(mapOf("first" to listOf(encoded)), parsed.selectForCredentials(setOf("first")))
    }

    @Test
    fun rejectsUnknownTypesByDefaultIncludingRetiredProfiles() {
        for (name in listOf(type, "qes_authorization", "qcert_creation_acceptance")) {
            val objectValue = JsonObject(payload() + ("type" to JsonPrimitive(name)))
            val error = assertFailsWith<InvalidTransactionDataException> {
                TransactionDataWrapper.fromValue(request(listOf(encode(objectValue))))
            }
            assertEquals("invalid_transaction_data", error.code)
        }
    }

    @Test
    fun rejectsMalformedEntriesInsteadOfDroppingThem() {
        for (bad in listOf("!", "e30=", encode(JsonArray(emptyList())), encode(JsonObject(emptyMap())))) {
            assertFailsWith<InvalidTransactionDataException> { parse(request(listOf(encode(payload()), bad))) }
        }
        for (bad in listOf("null", "[]", "{}", "[null]", "[123]")) {
            val value = Value.fromJsonElement(Json.parseToJsonElement("""{"transaction_data":$bad}"""))
            assertFailsWith<InvalidTransactionDataException> { parse(value) }
        }
    }

    @Test
    fun rejectsUnknownFieldsAndInvalidProfileValues() {
        for (bad in listOf(
            JsonObject(payload() + ("unknown" to JsonPrimitive(true))),
            JsonObject(payload() + ("amount" to JsonPrimitive(-1))),
            JsonObject(payload() - "amount"),
        )) assertFailsWith<InvalidTransactionDataException> { parse(request(listOf(encode(bad)))) }
    }

    @Test
    fun validatesCredentialReferencesAndHolderBinding() {
        for (ids in listOf(emptyList(), listOf("missing"))) {
            assertFailsWith<InvalidTransactionDataException> { parse(request(listOf(encode(payload(ids))))) }
        }
        for (query in listOf(
            """{"credentials":[{"id":"first","format":"dc+sd-jwt","require_cryptographic_holder_binding":false}]}""",
            """{"credentials":[{"id":"first","format":"mso_mdoc"}]}""",
            """{"credentials":[{"id":"first","format":"dc+sd-jwt","require_cryptographic_holder_binding":"true"}]}""",
        )) assertFailsWith<InvalidTransactionDataException> { parse(request(listOf(encode(payload())), query)) }
    }

    @Test
    fun acceptsOnlyHashAlgorithmListsThatPermitSha256() {
        parse(request(listOf(encode(payload()))))
        parse(request(listOf(encode(payload(algorithms = JsonArray(listOf(JsonPrimitive("sha-512"), JsonPrimitive("sha-256"))))))))
        for (bad in listOf(JsonArray(emptyList()), JsonArray(listOf(JsonPrimitive("sha-512"))), JsonPrimitive("sha-256"), JsonNull)) {
            assertFailsWith<InvalidTransactionDataException> { parse(request(listOf(encode(payload(algorithms = bad))))) }
        }
    }

    @Test
    fun requestParserPropagatesInvalidTransactionData() {
        val request = request(listOf(encode(payload())))
        assertFailsWith<InvalidTransactionDataException> { PresentationRequest.fromValue(request) }
        assertNotNull(PresentationRequest.fromValue(request, profiles)?.transactionData)
        assertNull(TransactionDataWrapper.fromValue(Value.Object(emptyMap())))
    }
}
