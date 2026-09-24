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

package org.kapunsdk.trust.framework.swiss

import org.kapunsdk.trust.did.DidResolver
import org.kapunsdk.trust.framework.swiss.dto.IssuanceTrustStatementsDto
import org.kapunsdk.trust.framework.swiss.dto.VerificationTrustStatementsDto
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.appendPathSegments
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import uniffi.kapun_crypto_rust.DidVerificationDocument

internal class SwissTrustService(
	private val httpClient: HttpClient,
) {

	companion object {
		val koinModule = module {
			singleOf(::SwissTrustService)
		}

		private const val WELL_KNOWN_PATH = "/.well-known"
		private const val TRUST_STATEMENT_PATH = "$WELL_KNOWN_PATH/trust-statement"
		private const val TRUST_API_PATH = "/api/v1/truststatements"
		private const val TRUST_API_V2_NON_COMPLIANCE_PATH = "/api/v2/non-compliance-trust-list"
		private val DID_REGEX = Regex("did:(tdw|webvh):(?<integrity>[^:]+):(?<domain>[A-z0-9-_.]+)(:(?<path>[^#]+))?(#(?<fragment>.*))?")
	}

	suspend fun getIssuanceTrustStatements(baseUrl: String): IssuanceTrustStatementsDto {
		val url = URLBuilder(baseUrl).apply {
			appendPathSegments(TRUST_STATEMENT_PATH)
		}.build()

		return httpClient.get(url).body<IssuanceTrustStatementsDto>()
	}

	suspend fun getVerificationTrustStatements(baseUrl: String): VerificationTrustStatementsDto {
		val url = URLBuilder(baseUrl).apply {
			appendPathSegments(TRUST_STATEMENT_PATH)
		}.build()

		return httpClient.get(url).body<VerificationTrustStatementsDto>()
	}

	suspend fun getTrustFromDid(
		did: String,
		configuration: SwissTrustConfiguration,
	): List<String> {
		return kotlin.runCatching {
			val apiBaseUrl = deriveTrustStatementApiBaseUrl(did)
				?.takeIf { configuration.allowsApiBaseUrl(it) }
				?: return@runCatching emptyList<String>()
			val url = URLBuilder(apiBaseUrl).apply {
				appendPathSegments(TRUST_API_PATH)
				appendPathSegments(did, encodeSlash = true)
			}.build()

			val result = httpClient.get(url).bodyAsText()
			return Json.Default.decodeFromString(result)
		}.getOrDefault(emptyList())
	}

	/**
	 * Returns the current Swiss Trust Protocol 2.0 non-compliance trust-list
	 * statement.  The statement is deliberately returned as a JWT string; the
	 * repository validates its signature, profile version, lifetime and status
	 * before using it.
	 */
	suspend fun getNonComplianceTrustListStatement(
		statementIssuer: String,
		configuration: SwissTrustConfiguration,
	): String? {
		return runCatching {
			val apiBaseUrl = deriveTrustStatementApiBaseUrl(statementIssuer)
				?.takeIf { configuration.allowsApiBaseUrl(it) }
				?: return@runCatching null
			httpClient.get(URLBuilder(apiBaseUrl).apply {
				appendPathSegments(TRUST_API_V2_NON_COMPLIANCE_PATH)
			}.build()).bodyAsText()
		}.getOrNull()
	}

	internal fun deriveTrustStatementApiBaseUrl(did: String): String? {
		val matches = DID_REGEX.matchEntire(did) ?: return null
		val domain = matches.groups["domain"]?.value ?: return null
		val trustRegistryDomain = if (domain.startsWith("identifier-reg.")) {
			"trust-reg.${domain.removePrefix("identifier-reg.")}"
		} else {
			domain
		}
		return "https://$trustRegistryDomain"
	}

	suspend fun getDidDocument(did: String): DidVerificationDocument? {
		return runCatching {
			val matches = DID_REGEX.matchEntire(did) ?: return@runCatching null
			val url = matches.groups["domain"]?.value ?: return@runCatching null
			val path = matches.groups["path"]?.value?.replace(":", "/")?.let {
				"$it/did.jsonl"
			}
			val keyUrl = URLBuilder("https://$url").apply {
				if (path != null) {
					appendPathSegments(path)
				} else {
					appendPathSegments(".well-known/did.jsonl")
				}
			}.build()
			val res = httpClient.get(keyUrl) {
				headers {
					append(HttpHeaders.Accept, "application/jsonl+json")
				}
			}.body<String>()

			// JSONL responses commonly end with a newline. Do not pass the
			// resulting empty line to DidLogEntry.parse(), otherwise a valid
			// WebVH log is rejected before it can be resolved.
			val jsonl = res.lineSequence()
				.map { it.trim() }
				.filter { it.isNotEmpty() }
				.toList()
			val resolver = DidResolver.fromJsonL(jsonl)
			resolver.resolveLatest().doc()
		}.getOrNull()
	}

}
