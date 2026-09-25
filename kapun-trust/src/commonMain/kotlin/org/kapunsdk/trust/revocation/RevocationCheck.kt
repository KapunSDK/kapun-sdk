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

package org.kapunsdk.trust.revocation

import org.kapunsdk.trust.framework.swiss.SwissTrustService
import org.kapunsdk.trust.di.KapunTrustKoinComponent
import org.kapunsdk.util.log.Logger
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.koin.core.component.inject
import uniffi.kapun_issuance_rust.StatusListException
import uniffi.kapun_issuance_rust.StatusListVerifier
import uniffi.kapun_crypto_rust.DidVerificationDocument
import uniffi.kapun_crypto_rust.parseEncodedJwtHeader
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

class RevocationCheck : KapunTrustKoinComponent {
	companion object {
		val koinModule = module {
			singleOf(::RevocationCheck)
		}
	}

    private val httpClient by inject<HttpClient>()
    private val json by inject<Json>()
    private val cache by inject<RevocationCache>()
    private val trustService by inject<SwissTrustService>()
    suspend fun check(
        url: String,
        index: Int,
        expectedIssuer: String? = null,
        didDocument: DidVerificationDocument? = null,
    ) : Boolean {
        return runCatching {
            if (expectedIssuer == null) {
                cache.getResult(url, index)?.let { return it }
            }
            val cachedStatusList = cache.getList(url)
            val statusListToken = cachedStatusList ?:
                httpClient.get(url) { accept(ContentType("application", "statuslist+jwt")) }
                    .bodyAsText()
            if (cachedStatusList == null) {
                cache.insertList(url, statusListToken)
            }
            val statusListIssuer = extractStatusListIssuer(statusListToken, json)
            if (expectedIssuer != null) {
                if (statusListIssuer != normalizeIssuer(expectedIssuer)) {
                    return@runCatching true
                }
            }
            val jwt = StatusListVerifier(statusListToken)
            try {
                if (statusListIssuer?.startsWith("did:") == true) {
                    val statusListDidDocument = didDocument
                        ?: trustService.getDidDocument(statusListIssuer)
                        ?: return@runCatching true
                    jwt.validForDidDoc(statusListDidDocument)
                } else {
                    jwt.valid()
                }
                val statusList= jwt.getPayload()
                val isRevoked = statusList.isRevoked(index)
                cache.insertResult(url, index, isRevoked)
                return isRevoked
            } catch (e: StatusListException) {
                // jwt has an issue
                Logger("Status list").error("$e")
                return true
            }
        }.getOrNull() ?: true
    }

    private fun normalizeIssuer(value: String): String =
        value.removePrefix("decentralized_identifier:").substringBefore('#')
}

internal fun extractStatusListIssuer(statusListToken: String, json: Json): String? =
    parseEncodedJwtHeader(statusListToken)?.let {
        json.decodeFromString<JsonObject>(it)["kid"]?.jsonPrimitive?.contentOrNull
    }?.removePrefix("decentralized_identifier:")?.substringBefore('#')
