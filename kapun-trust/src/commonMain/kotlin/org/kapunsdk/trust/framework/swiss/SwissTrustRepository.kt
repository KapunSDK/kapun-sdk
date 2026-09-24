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

import org.kapunsdk.credentials.SdJwt
import org.kapunsdk.issuance.jwt.JwtParser
import org.kapunsdk.issuance.metadata.data.CredentialConfiguration
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadata
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.framework.swiss.dto.VerificationTrustStatementsDto
import org.kapunsdk.trust.framework.swiss.model.TrustData
import org.kapunsdk.trust.framework.swiss.model.TrustStatementHeader
import org.kapunsdk.trust.framework.swiss.model.TrustStatementPayload
import org.kapunsdk.trust.framework.swiss.model.TrustStatementStatus
import org.kapunsdk.trust.framework.swiss.model.IdentityTrustStatement
import org.kapunsdk.trust.framework.swiss.model.NonComplianceTrustListStatement
import org.kapunsdk.trust.framework.swiss.model.ProtectedVerificationAuthorizationTrustStatement
import org.kapunsdk.trust.framework.swiss.model.TrustedIdentity
import org.kapunsdk.trust.framework.swiss.model.TrustedIdentityV2
import org.kapunsdk.trust.framework.swiss.model.TrustedIssuance
import org.kapunsdk.trust.framework.swiss.model.TrustedVerification
import org.kapunsdk.trust.framework.swiss.model.VerificationQueryPublicStatement
import org.kapunsdk.trust.framework.swiss.model.fromV2
import org.kapunsdk.trust.framework.swiss.allowsApiBaseUrl
import org.kapunsdk.trust.framework.swiss.allowsStatementIssuer
import org.kapunsdk.trust.di.KapunTrustKoinComponent
import org.kapunsdk.trust.model.AgentInformation
import org.kapunsdk.trust.model.AgentType
import org.kapunsdk.trust.revocation.RevocationCheck
import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.transform
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.koin.core.module.dsl.singleOf
import org.koin.core.component.inject
import org.koin.dsl.module
import uniffi.kapun_crypto_rust.getKidFromJwt
import uniffi.kapun_crypto_rust.parseEncodedJwtHeader
import uniffi.kapun_crypto_rust.parseEncodedJwtPayload
import uniffi.kapun_crypto_rust.validateJwtWithDidDocument
import uniffi.kapun_credential_core_rust.PointerPart
import org.kapunsdk.DcqlQuerySerializer
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import uniffi.kapun_crypto_rust.DidVerificationDocument

/**
 * Implements trust protocols based on the Swiss Trust Infrastructure proposal (https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/rfcs/trust-protocol/trust-protocol.md)
 */
@OptIn(ExperimentalTime::class)
internal class SwissTrustRepository(
	private val trustService: SwissTrustService,
	private val json: Json,
) : KapunTrustKoinComponent {

	private val revocationCheck by inject<RevocationCheck>()

	companion object {
		val koinModule = module {
			singleOf(::SwissTrustRepository)
		}
		private const val SWISS_PROFILE_TRUST_VERSION_PREFIX = "swiss-profile-trust:"
		private const val IDENTITY_TRUST_STATEMENT_TYPE = "swiyu-identity-trust-statement+jwt"
		private const val VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE = "swiyu-verification-query-public-statement+jwt"
		private const val PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE =
			"swiyu-protected-verification-authorization-trust-statement+jwt"
		private const val NON_COMPLIANCE_TRUST_LIST_STATEMENT_TYPE =
			"swiyu-non-compliance-trust-list-statement+jwt"
		private const val VERIFIED_IDENTITY_MARKER = "viTM"
		private const val COMPLIANT_ACTOR_MARKER = "caTM"
		private const val TRANSPARENT_VERIFICATION_MARKER = "tvTM"
		private const val GOVERNED_USE_CASE_MARKER = "gucTM"
		private const val GOVERNED_USE_CASE_AUTHORIZATION_MARKER = "gucaTM"
		private val PROTECTED_FIELDS = setOf("personal_administrative_number")
		private val UUID_V4_REGEX = Regex(
			"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
		)
		val TRUST_JWT_BETA_CREDENTIAL_SERVICE = "eyJ0eXAiOiJKV1QiLCJraWQiOiJ6dUQzZGkwZzVudDUxZnpIekNkaVpaSzlOUGFyY3pDQ1J6MkhkVGFRYzZnIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJiY3MuYWRtaW4uY2gvYmNzLXdlYi9pc3N1ZXItYWdlbnQvb2lkNHZjaSIsInByZWZMYW5nIjoiZGUiLCJ2Y3QiOiJUcnVzdFN0YXRlbWVudElkZW50aXR5VjEiLCJlbnRpdHlOYW1lIjp7ImRlIjoiQmV0YSBDcmVkZW50aWFsIFNlcnZpY2UiLCJlbiI6IkJldGEgQ3JlZGVudGlhbCBTZXJ2aWNlIn0sImlzcyI6ImUtaWQtYWRtaW46aXNzdWVyIiwibG9nb1VyaSI6eyJkZSI6ImRhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpVkJPUncwS0dnb0FBQUFOU1VoRVVnQUFBR1FBQUFCa0NBWUFBQUJ3NHBWVUFBQUdEa2xFUVZSNDJ1MmRhNGhWVlJUSHQrWE1QV3RiV2Nob09lVmo1dHl6TmxsKzhJYVBtYm5uckJWUlZFUlFVRmFXNUtQVXpBZWtwcFFEQnFZWmxSWVU5RVZONkVOV1VCU1pSWWxZZ1Qya3BKUXNGQ0tEbEV3czB6TDc0QVE5Wjd6M3JIUFB1ZWV1UDZ6djYremZYWGZ0dGZmYWV4dWpVcWxVcW9wMDRRUW90SVZGenhFQmhqZlpnR2Q1QVMrRmdOZFl4K3ZBOFl2VzhTWkEzbWFSZDFqSE93RjVGeUR2QWNkN3dmRStRTjREeUx1czQ1MFdlUWM0ZXM4NmVoTWN2UVRJNjhIUmsxNUEzVGFnZXlDZ216ME1MeTlnSjVvaG93YzA1cUMzamgza0ZjUFFDNkxwZ05GS1FOcG9rVDZ4amc5YXh5ZFROYVFmTE5LbmdQUXlJSzJ5U0RNOGpOaTBkd3pPdzlEM0s3UjFCVkNNYmdHa1ZZRDBsblg4WGVxRFhyMGRBRWZ2QXRMakh0S2tacjk4c1RHbVg0Ykh2OVFFTHV6d0hDK3h5SzlsNGhlZmVFVHhJZXQ0a3hmd1VzL255UGgrSVZVRWhiYXdDRWh6TGRMcjRQaW4zQVBvd3dEcHFIVzBHUnpkMXhOQnlhdkpMNCt4anBmM0pNNlRhcjBCNHE4Z29FZkJwL0d5RkViUXVWNFFMVllJc2FMbmF5K2didU9YVzJMenNNalg2NkRLbUlmUm5iR0JRRUFUZFRDbEpnTFJ6TmhBdkNDOFF3ZFQ3SzlyWG53Z1NGTjFNS1dBUkFzRWNnak4wTUVVeWlGQnREZytrSUJuNldCS0pYVjZRQ0twejg3QU90UG5Ib1pUNGhnNDNwMStoUERTK0VCY2RHOEdpcXkzNDM4SGIwa2ZDSFhuSWtMeUEwUWdRcktRUTNJREJLTUhjekhMeWcwUXgwc0VDa09hcGtERXZtT2hCSkRKQ2tUb080Sm92c0FzSzd4VmdVZ0JvZG54Z1JUREd4U0kyTFIzV3Z5ZHdTQzZXb0dJVmVxVEJCWVhJMVlnUXQvaCtFYUphZTlsQ2tUR0NuNTRwVWd6Z3dJUitvNGlqNHUvcDk3ZU1WaUJ5Rmh6UUU2Z3kyRlVzd0tSTVRPOGZJRkk0OG1wbmlNRkVodkkwSklWQVpKMkcyZ2VnSUNqNDJLdFdXbHY3dVFpUXBDK0Z3UkM3eXVRMkRYSWJqa2dTQnVyY0dBTE9IcFl3anlrcVFKL3UzZEorUU5JVzZ0b0FYcEhFRWkwT3BXMS80ektDNmk3Q2lBYkJJSHdRZ1VTRjBpMFVzNEJwTnNVU0Z3Z1BFZk9BVWVrUUdJQ2tWaFlqTE9lcFVEK0FVVDBuTWpRa2xVZ01ZRzBoeGVKT21FZDdWY2cxUUVCcEtQR21ET2xnV3hXSU5WR0NIMHM3Z1FnUGFGQXFvMFFYcCtFRTlNVVNOVkFGc3BIaUUvakZVaDFRQXBCZUkyOEY5aDVOaUQ5cmtDcWlKQzJybUdKT0FLTzl5cVF5b0FBMHVIRUhMR09YbFVnbFFMaGJZazVBZ0hkcjBBcWpwQlZ5UUZ4WVVjRmw3TXNNMjJsZ1NJbWNaL1ZrTkVEcFB5eGpwZWZmZzZKcmt2d3R6R3FHWkIrMWgzRDAvYjdoQm5XZFY2aTRXcVIzbEFncC8xM3RUM3gvMCtMMFV3RlVzTmowSDBuOWdtdGxkUWpqUXlrMllXWDFtU1dBWTQrVUNCOTltRjlXY05wWHpSZGdmU1pQeGJWYmlMZVFtY0IwbUVGMGt1WDRzaHhRMnBiSENFOW8wRCtOenBlcUhtMTJuUC9vZ0w1NzdPRVY2U3loQUJJMnhYSXYzemRZOUs2MDdkV0ozVHJDWWpJU2RzWTZ0ZHpWYmdDNmJsOTFKaFNVNm9ybjdXNHRiUmVnSGdZVHNuRWNyUjEvRkdqQXptVk82aC9Kb0FVaW54dG93UHhndWoyVEczYUFOSXJqUW9Fa0xhYXJMMlc0STNzR0o3VXBmeFpCZ0tPZm0xdXAwc3l1YlVKU0lzYURvamt1UTk1bFpxczQ1Mk5BZ1FjNzh2OGMwbE5mbmtNT0Q0bS9PSEhlbzVtVjIzZzZMajA5cXlIRWRkRlZ3WWd6V3VBRjNhVzFWV3JUQ1U5WEhWNHFmNVdJMzI4SUhHMWpoMEV5Ti9rRU1oQjhjTTNOYXpnUzNsNm53b2NIYStidk5IYldoY2duOGpINndZMDJlUkJFRVR6NnorSjAwTW1Ud0xIajlVdkVGcHJzdjJRWkxXUndtdnFjRWIxbkRIbURKTlhnYU9uNmdqR2hsekQrSE9Yc1pyTGJGS3dkZlZYYThTcTVxTUZ0VzVKcmNDV20wWVVCRFJSZXQwcjV2clViOWJSM2FhUkJRRjFXVWZmWnFFQ0x6aSt5cWlNTVNQby9KU3Y0UHZRY3pSQ1FmeE4xQitRSDZsMVZlOGhQWjM2VytoWmx1ZHpWTW54NnhqRjN2NWtEdlRuVWY2NGN5elNzMG5Od3NEUjg2WjE3Q0FkNklxbnh0eHBIWDBtZVloRzVJVUN6UzA4eHpvK0VHTjM3MGN2aUJacnJwQlVXMmtnSUswQXgwY3FxQ3QrZ1lEWEdML2NvZ09ZV0g0cHR3RFNDb3Q4cUplbWlDT0EwV3FMblVOMXdHcWxVN2NUelFXa0wvN2FmUTVJaXhJL3JLL3FJL243MFFUUEVaazg3bG1vVkNxVlNxV3FYLzBCblNaYkZ4YWVIN2dBQUFBQVNVVk9SSzVDWUlJPSJ9LCJpYXQiOjE3NDUzOTA1NjZ9.3BSbrVqVI9Ka3UyvUZNzgL7XnDWl1MiPZRXe3H8ZCMN9aVHxCtol2CSBT5MLyw8OGmjYb38om_UsBghclfm_gA"
	}

	suspend fun getIssuerInformationFromSignedMetadata(
		metadata: CredentialIssuerMetadata.Signed,
		configuration: SwissTrustConfiguration = SwissTrustConfiguration(),
	): AgentInformation? {
		val host = Url(metadata.originalUrl).host
		val kid = getKidFromJwt(metadata.originalJwt) ?: return null
		val did = trustService.getDidDocument(kid) ?: return null
		val verified = validateJwtWithDidDocument(metadata.originalJwt, did, false)
		val issuerDid = normalizeDid(kid).substringBefore('#')
		val identityJwt = metadata.claims.credentialIssuerIdentityTrustStatement
		val identity = identityJwt?.let {
			validateStatement(it, IDENTITY_TRUST_STATEMENT_TYPE, issuerDid, configuration) {
				json.decodeFromString<IdentityTrustStatement>(it)
			}
		}
		val displayName = identity?.let(::trustedIdentityFromStatement)?.entityName?.values?.firstOrNull()
			?: metadata.claims.display?.firstOrNull()?.name
			?: host
		val displayLogo = identity?.let(::trustedIdentityFromStatement)?.logoUri?.values?.firstOrNull()
			?: metadata.claims.display?.firstOrNull()?.logo?.uri
		return AgentInformation(
			type = AgentType.ISSUER,
			domain = host,
			displayName = displayName,
			logoUri = displayLogo,
			isTrusted = verified && (identityJwt == null || identity != null),
			isVerified = verified && (identityJwt == null || identity != null),
			identityTrust = identityJwt,
			trustFrameworkId = SWISS_TRUST_FRAMEWORK_ID
		)
    }

	suspend fun getIssuanceTrustData(
		url: String,
		credentialConfigurationIds: List<String>,
		supportedCredentialConfigurations: Map<String, CredentialConfiguration>,
		configuration: SwissTrustConfiguration = SwissTrustConfiguration(),
	): TrustData.Issuance? = withContext(Dispatchers.IO) {
		val baseUrl = runCatching { Url(url).host }.getOrDefault(url)

		val trustStatements = try {
			trustService.getIssuanceTrustStatements(url)
		} catch (e: Exception) {
			if(baseUrl == "bcs.admin.ch") {
				val trustedIdentityJson = parseEncodedJwtPayload(TRUST_JWT_BETA_CREDENTIAL_SERVICE)
					?: return@withContext null
				val trustedIdentity = json.decodeFromString<TrustedIdentity>(trustedIdentityJson)
				return@withContext TrustData.Issuance(
					baseUrl = "bcs.admin.ch/bcs-web/issuer-agent/oid4vci",
					identity = trustedIdentity,
					identityJwt = TRUST_JWT_BETA_CREDENTIAL_SERVICE,
					issuance = null,
					issuanceJwt = null,
					isTrusted = true,
					isVerified = true
				)
			}
			return@withContext null
		}

		val encodedIdentityTrustStatementJwt = trustStatements.identity
		val trustedIdentityJwt = JwtParser(encodedIdentityTrustStatementJwt)
		val trustedIdentity = trustedIdentityJwt.getPayload()?.let {
			json.decodeFromString<TrustedIdentity>(it)
		}

		val encodedIssuanceTrustStatementJwt = trustStatements.issuance
		val trustedIssuanceJwt = encodedIssuanceTrustStatementJwt?.let { JwtParser(it) }
		val trustedIssuance = trustedIssuanceJwt?.getPayload()?.let {
			json.decodeFromString<TrustedIssuance>(it)
		}

		//TODO (but not for showcase): isTrusted should only be true if it is still valid: trustedIdentity.exp > Clock.System.now().toEpochMilliseconds() && trustedVerification.exp > Clock.System.now().toEpochMilliseconds()
		val isTrusted = trustedIdentityJwt.isSignatureValid("JWT")

		// Match the credential configuration IDs from the credential offer with the ones in the credential issuer metadata and then check if their VCT or DocType matches the ones in the trust statement
		val isCredentialConfigurationAllowed = credentialConfigurationIds.any { credentialConfigurationId ->
			supportedCredentialConfigurations[credentialConfigurationId]
				?.let {
					when (it) {
						is CredentialConfiguration.Mdoc -> trustedIssuance?.schemaIds?.contains(it.doctype) ?: (trustedIssuance?.schemaId == it.doctype)
						is CredentialConfiguration.SdJwt -> trustedIssuance?.schemaIds?.contains(it.vct) ?: (trustedIssuance?.schemaId == it.vct)
						else -> it.format == "zkp_vc"
					}
				} ?: false
		}

		val isVerified = trustedIdentity != null
				&& trustedIssuance != null
				&& trustedIssuance.sub == trustedIdentity.sub
				&& trustedIssuanceJwt.isSignatureValid("JWT")
				&& isCredentialConfigurationAllowed

		return@withContext TrustData.Issuance(
			baseUrl = baseUrl,
			identity = trustedIdentity,
			identityJwt = encodedIdentityTrustStatementJwt,
			issuance = trustedIssuance,
			issuanceJwt = encodedIssuanceTrustStatementJwt,
			isTrusted = isTrusted,
			isVerified = isVerified
		)
	}

	suspend fun getVerificationTrustData(
		url: String,
		presentationRequest: PresentationRequest,
		originalRequest: String?,
		configuration: SwissTrustConfiguration = SwissTrustConfiguration(),
	): TrustData.Verification? = withContext(Dispatchers.IO) {
		val baseUrl = runCatching { Url(url).host }.getOrDefault(url)
		getVerificationTrustDataFromVerifierInfo(
			baseUrl,
			presentationRequest,
			originalRequest,
			configuration,
		)?.let {
			return@withContext it
		}
		val trustStatements = kotlin.runCatching { trustService.getVerificationTrustStatements(url) }.getOrNull()
		if(trustStatements != null) {
			return@withContext getOldVerificationTrustData(baseUrl, trustStatements)
		} else {
			// check presentation request integrity
			val presentationDidDoc = trustService.getDidDocument(did = presentationRequest.clientId)
			if(presentationDidDoc == null) {
				return@withContext null
			}
			val isTrusted = originalRequest?.let { validateJwtWithDidDocument(originalRequest, presentationDidDoc, true) } ?: return@withContext null

			val trustedIdentityJwt = trustService
				.getTrustFromDid(presentationRequest.clientId, configuration)
				.firstOrNull()
			val trustedIdentitySdJwt = trustedIdentityJwt?.let { SdJwt.parse(it) }

			val didDoc = trustedIdentitySdJwt?.let { trustService.getDidDocument(did = trustedIdentitySdJwt.innerJwt.claims["iss"].asString()!!) }
			val isVerified = didDoc?.let { validateJwtWithDidDocument(trustedIdentitySdJwt.innerJwt.originalJwt, didDoc, true) }
			val trustedIdentity : TrustedIdentityV2? = isVerified?.let {  trustedIdentitySdJwt.innerJwt.claims.transform<TrustedIdentityV2>() }
			return@withContext TrustData.Verification(
				baseUrl = baseUrl,
				identity = trustedIdentity?.let { TrustedIdentity.fromV2(it) } ,
				identityJwt = trustedIdentityJwt,
				verification = null,
				verificationJwt = null,
				isTrusted = isTrusted,
				isVerified = isVerified ?: false
			)
		}
	}

	private data class ValidatedStatement<T : TrustStatementPayload>(
		val jwt: String,
		val type: String,
		val issuer: String,
		val payload: T,
	)

	private fun verifierInfoJwts(presentationRequest: PresentationRequest): List<String> =
		presentationRequest.verifierInfo.orEmpty().mapNotNull { verifierInfo ->
			if (verifierInfo["format"].asString() != "jwt" ||
				verifierInfo["credential_ids"] != uniffi.kapun_util_rust.Value.Null
			) return@mapNotNull null
			verifierInfo["data"].asString()
		}

	private fun statementType(jwt: String): String? = runCatching {
		json.decodeFromString<TrustStatementHeader>(parseEncodedJwtHeader(jwt) ?: return@runCatching null).typ
	}.getOrNull()

	private fun normalizeDid(value: String): String =
		value.removePrefix("decentralized_identifier:")

	private suspend fun <T : TrustStatementPayload> validateStatement(
		jwt: String,
		expectedType: String,
		expectedSubject: String? = null,
		configuration: SwissTrustConfiguration,
		decodePayload: (String) -> T,
	): ValidatedStatement<T>? = runCatching {
			val header = json.decodeFromString<TrustStatementHeader>(
				parseEncodedJwtHeader(jwt) ?: return@runCatching null
			)
			if (header.typ != expectedType) return@runCatching null
			if (header.alg != "ES256") return@runCatching null
			if (!header.profileVersion.startsWith(SWISS_PROFILE_TRUST_VERSION_PREFIX)) {
				return@runCatching null
			}
			val issuer = normalizeDid(header.kid).substringBefore('#')
			if (!configuration.allowsStatementIssuer(issuer)) return@runCatching null
			if (!trustService.deriveTrustStatementApiBaseUrl(issuer)
					.let { it != null && configuration.allowsApiBaseUrl(it) }) {
				return@runCatching null
			}
			val payload = decodePayload(parseEncodedJwtPayload(jwt) ?: return@runCatching null)
			val subject = payload.sub
			if (expectedSubject != null &&
				(subject == null || normalizeDid(subject) != normalizeDid(expectedSubject))) {
				return@runCatching null
			}
			if (!payload.jti.matches(UUID_V4_REGEX)) {
				return@runCatching null
			}
			val now = Clock.System.now().epochSeconds
			if (payload.iat > now || payload.exp <= now || payload.exp <= payload.iat) return@runCatching null
			if (payload.nbf?.let { it > now } == true) {
				return@runCatching null
			}
			val didDocument = trustService.getDidDocument(header.kid) ?: return@runCatching null
			if (!validateJwtWithDidDocument(jwt, didDocument, false)) return@runCatching null
			if (!validateStatementStatus(
				payload.status,
				expectedType,
				issuer,
				didDocument,
			)) return@runCatching null
			ValidatedStatement(jwt, expectedType, issuer, payload)
		}.getOrNull()

	private suspend fun validateStatementStatus(
		status: TrustStatementStatus?,
		type: String,
		statementIssuer: String,
		didDocument: DidVerificationDocument,
	): Boolean {
		if (status == null) return type == VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE
		return !revocationCheck.check(
			status.statusList.uri,
			status.statusList.idx.toInt(),
			statementIssuer,
			didDocument,
		)
	}

	private suspend fun getVerificationTrustDataFromVerifierInfo(
		baseUrl: String,
		presentationRequest: PresentationRequest,
		originalRequest: String?,
		configuration: SwissTrustConfiguration,
	): TrustData.Verification? {
		val verifierInfo = verifierInfoJwts(presentationRequest)
		val types = verifierInfo.mapNotNull(::statementType)
		val hasSwissProfileRequest = presentationRequest.scope != null || types.any {
			it == IDENTITY_TRUST_STATEMENT_TYPE ||
				it == VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE ||
				it == PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE
		}
		if (!hasSwissProfileRequest) return null

		val clientId = normalizeDid(presentationRequest.clientId)
		val identity = verifierInfo
			.filter { statementType(it) == IDENTITY_TRUST_STATEMENT_TYPE }
			.singleOrNull()
			?.let {
				validateStatement(it, IDENTITY_TRUST_STATEMENT_TYPE, clientId, configuration) {
					json.decodeFromString<IdentityTrustStatement>(it)
				}
			}

		val verificationQuery = verifierInfo
			.filter { statementType(it) == VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE }
			.singleOrNull()
			?.let {
				validateStatement(it, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE, clientId, configuration) {
					json.decodeFromString<VerificationQueryPublicStatement>(it)
				}
			}
		val hasValidVerificationQuery = verificationQuery?.let {
			isVerificationQueryForRequest(it, presentationRequest)
		} == true

		val protectedAuthorizationStatements = verifierInfo
			.filter { statementType(it) == PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE }
			.mapNotNull {
				validateStatement(it, PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE, clientId, configuration) {
					json.decodeFromString<ProtectedVerificationAuthorizationTrustStatement>(it)
				}
			}
		val protectedClaims = protectedClaims(presentationRequest.dcqlQuery)
		val hasGovernedUseCase = protectedClaims.isNotEmpty()
		val hasGovernedUseCaseAuthorization = !hasGovernedUseCase || protectedClaims.all { claim ->
			protectedAuthorizationStatements.any { statement ->
				statement.payload.authorizedFields.contains(claim)
			}
		}

		val nonComplianceJwt = identity?.issuer
			?.let { issuer ->
				runCatching {
					trustService.getNonComplianceTrustListStatement(issuer, configuration)
				}.getOrNull()
			}
		val nonCompliance = nonComplianceJwt?.let {
			validateStatement(it, NON_COMPLIANCE_TRUST_LIST_STATEMENT_TYPE, configuration = configuration) {
				json.decodeFromString<NonComplianceTrustListStatement>(it)
			}
		}
		val isCompliant = nonCompliance?.let {
			it.payload.nonCompliantActors.none { actor ->
				normalizeDid(actor.actor) == clientId
			}
		} == true

		val requestIntegrity = originalRequest?.let {
			validateSignedRequest(it, clientId)
		} == true
		val markers = buildList {
			if (identity != null) add(VERIFIED_IDENTITY_MARKER)
			if (hasValidVerificationQuery) add(TRANSPARENT_VERIFICATION_MARKER)
			if (hasGovernedUseCase) add(GOVERNED_USE_CASE_MARKER)
			if (hasGovernedUseCase && hasGovernedUseCaseAuthorization) {
				add(GOVERNED_USE_CASE_AUTHORIZATION_MARKER)
			}
			if (isCompliant) add(COMPLIANT_ACTOR_MARKER)
		}
		val scopeRequirementSatisfied = presentationRequest.scope == null || hasValidVerificationQuery
		val isTrusted = requestIntegrity && identity != null && scopeRequirementSatisfied &&
			hasGovernedUseCaseAuthorization && (nonComplianceJwt == null || isCompliant)
		return TrustData.Verification(
			baseUrl = baseUrl,
			identity = identity?.let(::trustedIdentityFromStatement),
			identityJwt = identity?.jwt,
			verification = null,
			verificationJwt = verificationQuery?.jwt,
			verificationQueryJwt = verificationQuery?.jwt,
			protectedVerificationAuthorizationJwts = protectedAuthorizationStatements.map { it.jwt },
			trustMarkers = markers,
			isTrusted = isTrusted,
			isVerified = identity != null && scopeRequirementSatisfied && hasGovernedUseCaseAuthorization
		)
	}

	private suspend fun validateSignedRequest(
		request: String,
		clientId: String,
	): Boolean = runCatching {
			// Resolve the DID from the request signer. This handles a key-bearing
			// `kid` and avoids making DID-document lookup depend on the exact form of
			// the parsed client_id value.
			val requestKid = getKidFromJwt(request) ?: return@runCatching false
			val requestDid = normalizeDid(requestKid).substringBefore('#')
			val clientDid = normalizeDid(clientId).substringBefore('#')
			if (requestDid != clientDid) {
				return@runCatching false
			}
			val didDocument = trustService.getDidDocument(requestDid) ?: run {
				return@runCatching false
			}
			val verified = validateJwtWithDidDocument(request, didDocument, false)
			verified
		}.getOrDefault(false)

	private fun isVerificationQueryForRequest(
		statement: ValidatedStatement<VerificationQueryPublicStatement>,
		presentationRequest: PresentationRequest,
	): Boolean {
		val request = statement.payload.request
		val statementScope = request.scope
		val requestedScopes = presentationRequest.scope?.split(Regex("\\s+"))?.filter(String::isNotBlank).orEmpty()
		if (statementScope !in requestedScopes) return false
		val effectiveQuery = presentationRequest.dcqlQuery ?: return false
		return json.parseToJsonElement(DcqlQuerySerializer.toJson(request.query)) ==
			json.parseToJsonElement(DcqlQuerySerializer.toJson(effectiveQuery))
	}

	private fun protectedClaims(query: uniffi.kapun_dcql_rust.DcqlQuery?): List<String> =
		query?.credentials.orEmpty().flatMap { it.claims.orEmpty() }.mapNotNull { claim ->
			(claim.path.lastOrNull() as? PointerPart.String)?.v1
		}.filter(PROTECTED_FIELDS::contains)

	private fun trustedIdentityFromStatement(
		statement: ValidatedStatement<IdentityTrustStatement>,
	): TrustedIdentity {
		val payload = statement.payload
		return TrustedIdentity(
			vct = payload.vct,
			iss = payload.iss,
			sub = payload.sub,
			iat = payload.iat,
			nbf = payload.nbf,
			exp = payload.exp,
			status = payload.status?.let { json.encodeToString(TrustStatementStatus.serializer(), it) },
			entityName = mapOf("default" to payload.entityName),
			registryIds = payload.registryIds,
			logoUri = payload.logoUri?.let { mapOf("default" to it) },
			prefLang = payload.prefLang,
		)
	}

	internal suspend fun validatePresentationRequest(
		presentationRequest: PresentationRequest,
		configuration: SwissTrustConfiguration = SwissTrustConfiguration(),
	): org.kapunsdk.trust.framework.ValidationInfo {
		val hasSwissStatements = presentationRequest.scope != null || verifierInfoJwts(presentationRequest)
			.mapNotNull(::statementType).any {
				it == IDENTITY_TRUST_STATEMENT_TYPE ||
					it == VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE ||
					it == PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE
			}
		if (!hasSwissStatements) return org.kapunsdk.trust.framework.ValidationInfo(isValid = true)
		if (presentationRequest.scope != null && presentationRequest.dcqlQuery == null) {
			return org.kapunsdk.trust.framework.ValidationInfo(false, "No DCQL query matches the requested Swiss scope")
		}
		val trustData = getVerificationTrustDataFromVerifierInfo("", presentationRequest, null, configuration)
			?: return org.kapunsdk.trust.framework.ValidationInfo(false, "Missing Swiss Trust Protocol statements")
		val protected = protectedClaims(presentationRequest.dcqlQuery)
		val valid = trustData.trustMarkers.contains(VERIFIED_IDENTITY_MARKER) &&
			(presentationRequest.scope == null || trustData.trustMarkers.contains(TRANSPARENT_VERIFICATION_MARKER)) &&
			(protected.isEmpty() || trustData.trustMarkers.contains(GOVERNED_USE_CASE_AUTHORIZATION_MARKER))
		return org.kapunsdk.trust.framework.ValidationInfo(
			isValid = valid,
			errorInfo = if (valid) null else "Swiss Trust Protocol statements do not authorize this request",
			disallowedProperties = if (trustData.trustMarkers.contains(GOVERNED_USE_CASE_AUTHORIZATION_MARKER)) {
				emptyList()
			} else {
				presentationRequest.dcqlQuery?.credentials.orEmpty().flatMap { it.claims.orEmpty() }
					.filter { (it.path.lastOrNull() as? PointerPart.String)?.v1 in PROTECTED_FIELDS }
			}
		)
	}

	 suspend fun getOldVerificationTrustData(baseUrl: String, trustStatements: VerificationTrustStatementsDto) : TrustData.Verification? {
		val encodedIdentityTrustStatementJwt = trustStatements.identity
		val trustedIdentityJwt = JwtParser(encodedIdentityTrustStatementJwt)
		val trustedIdentity = trustedIdentityJwt.getPayload()?.let {
			json.decodeFromString<TrustedIdentity>(it)
		}

		val encodedVerificationTrustStatementJwt = trustStatements.verification
		val trustedVerification = encodedVerificationTrustStatementJwt?.let { jwt ->
			JwtParser(jwt).getPayload()?.let { payload ->
				jwt to json.decodeFromString<TrustedVerification>(payload)
			}
		}

		//TODO (but not for showcase): isTrusted should only be true if it is still valid: trustedIdentity.exp > Clock.System.now().toEpochMilliseconds() && trustedVerification.exp > Clock.System.now().toEpochMilliseconds()
		val isTrusted = isSdJwtSignatureValidWithIssuerDid(encodedIdentityTrustStatementJwt)
		val isVerified = trustedVerification != null
				&& trustedIdentity != null
				&& trustedIdentity.sub == trustedVerification.second.sub
				&& isSdJwtSignatureValidWithIssuerDid(trustedVerification.first)

		return TrustData.Verification(
			baseUrl = baseUrl,
			identity = trustedIdentity,
			identityJwt = encodedIdentityTrustStatementJwt,
			verification = trustedVerification?.second,
			verificationJwt = trustedVerification?.first,
			isTrusted = isTrusted,
			isVerified = isVerified
		)
	}

	private suspend fun isSdJwtSignatureValidWithIssuerDid(jwt: String): Boolean {
		return runCatching {
			val issuer = parseEncodedJwtPayload(jwt)
				?.let { json.decodeFromString<JsonObject>(it)["iss"]?.jsonPrimitive?.contentOrNull }
				?: return@runCatching false

			if (!issuer.startsWith("did:")) {
				return@runCatching JwtParser(jwt).isSignatureValid("vc+sd-jwt")
			}

			val didDocument = trustService.getDidDocument(issuer) ?: return@runCatching false
			validateJwtWithDidDocument(jwt, didDocument, false)
		}.getOrDefault(false)
	}

}
