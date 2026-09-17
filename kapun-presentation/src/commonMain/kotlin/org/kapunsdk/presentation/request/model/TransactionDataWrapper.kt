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

package org.kapunsdk.wallet.process.presentation.models

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.kapunsdk.presentation.request.model.InvalidTransactionDataException
import org.kapunsdk.presentation.request.model.TransactionData
import org.kapunsdk.presentation.request.model.TransactionDataProfile
import org.kapunsdk.util.extensions.*
import org.kapunsdk.util.extensions.get
import uniffi.kapun_util_rust.Value
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
sealed class TransactionDataWrapper {
    data class OpenId4Vp(val value: List<Pair<String, TransactionData>>) : TransactionDataWrapper()

    companion object {
        private val envelopeFields = setOf("type", "credential_ids", "transaction_data_hashes_alg")

        /** Unknown types and malformed entries fail the whole request; none are silently dropped. */
        @OptIn(ExperimentalEncodingApi::class)
        fun fromValue(
            value: Value,
            profiles: Map<String, TransactionDataProfile> = emptyMap(),
        ): TransactionDataWrapper? {
            if (value.asObject()?.containsKey("transaction_data") != true) return null
            fun invalid(message: String): Nothing = throw InvalidTransactionDataException(message)
            val entries = value["transaction_data"].asArray()
                ?: invalid("transaction_data must be an array")
            if (entries.isEmpty()) invalid("transaction_data must not be empty")
            val queryValue = value["dcql_query"].let { query ->
                query.asString()?.let { encoded ->
                    try { json.decodeFromString<Value>(encoded) }
                    catch (_: Exception) { invalid("Invalid DCQL query") }
                } ?: query
            }
            val queries = queryValue["credentials"].asArray()
                ?: invalid("Transaction data requires a DCQL query")
            val parsed = entries.map { entry ->
                val encoded = entry.asString() ?: invalid("Transaction data entries must be strings")
                if (encoded.isEmpty() || !encoded.matches(Regex("[A-Za-z0-9_-]+"))) {
                    invalid("Transaction data must be unpadded base64url")
                }
                val payload = try {
                    val bytes = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(encoded)
                    Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)) as? JsonObject
                        ?: invalid("Transaction data must contain a JSON object")
                } catch (e: InvalidTransactionDataException) { throw e }
                catch (_: Exception) { invalid("Invalid transaction-data encoding") }
                fun string(key: String): String = (payload[key] as? JsonPrimitive)
                    ?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }
                    ?: invalid("Missing or invalid $key")
                fun strings(key: String): List<String> {
                    val array = payload[key] as? JsonArray ?: invalid("Missing or invalid $key")
                    if (array.isEmpty()) invalid("$key must not be empty")
                    return array.map {
                        (it as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }
                            ?: invalid("$key must contain non-empty strings")
                    }
                }
                val type = string("type")
                val profile = profiles[type] ?: invalid("Unsupported transaction-data type: $type")
                if ((payload.keys - envelopeFields - profile.allowedFields).isNotEmpty()) {
                    invalid("Unknown fields for transaction-data type: $type")
                }
                val ids = strings("credential_ids")
                ids.forEach { id ->
                    val query = queries.singleOrNull { it["id"].asString() == id }
                        ?: invalid("Unknown or ambiguous credential ID: $id")
                    if (query.asObject()?.containsKey("require_cryptographic_holder_binding") == true
                        && query["require_cryptographic_holder_binding"].asBoolean() != true) {
                        invalid("Transaction data requires cryptographic holder binding")
                    }
                    if (query["format"].asString() !in setOf("dc+sd-jwt", "vc+sd-jwt")) {
                        invalid("Transaction-data hash profile requires SD-JWT credentials")
                    }
                }
                if ("transaction_data_hashes_alg" in payload && "sha-256" !in strings("transaction_data_hashes_alg")) {
                    invalid("Requested hash algorithms do not permit sha-256")
                }
                try { profile.validate(payload) }
                catch (e: Exception) { invalid("Invalid transaction data for $type: ${e.message}") }
                encoded to TransactionData(type, ids, payload)
            }
            return OpenId4Vp(parsed)
        }
    }

    /** Assign each transaction to exactly one of the selected eligible credentials. */
    fun selectForCredentials(selectedIds: Set<String>): Map<String, List<String>> {
        val entries = when (this) { is OpenId4Vp -> value }
        val result = mutableMapOf<String, MutableList<String>>()
        entries.forEach { (encoded, data) ->
            val id = data.credentialIds.firstOrNull { it in selectedIds }
                ?: throw InvalidTransactionDataException("No selected credential can authorize transaction ${data.type}")
            result.getOrPut(id) { mutableListOf() }.add(encoded)
        }
        return result
    }
}
