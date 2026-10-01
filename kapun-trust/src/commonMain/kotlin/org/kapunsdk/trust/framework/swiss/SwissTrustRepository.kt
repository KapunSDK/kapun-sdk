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

import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadata
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.framework.swiss.model.TrustData
import org.kapunsdk.trust.framework.swiss.model.TrustStatementHeader
import org.kapunsdk.trust.framework.swiss.model.TrustStatementPayload
import org.kapunsdk.trust.framework.swiss.model.TrustStatementStatus
import org.kapunsdk.trust.framework.swiss.model.IdentityTrustStatement
import org.kapunsdk.trust.framework.swiss.model.NonComplianceTrustListStatement
import org.kapunsdk.trust.framework.swiss.model.ProtectedVerificationAuthorizationTrustStatement
import org.kapunsdk.trust.framework.swiss.model.TrustedIdentity
import org.kapunsdk.trust.framework.swiss.model.VerificationQueryPublicStatement
import org.kapunsdk.trust.framework.swiss.allowsApiBaseUrl
import org.kapunsdk.trust.framework.swiss.allowsStatementIssuer
import org.kapunsdk.trust.di.KapunTrustKoinComponent
import org.kapunsdk.trust.did.getDidFromAbsoluteKid
import org.kapunsdk.trust.model.AgentInformation
import org.kapunsdk.trust.model.AgentType
import org.kapunsdk.trust.revocation.RevocationCheck
import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.get
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
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
		private const val DECENTRALIZED_IDENTIFIER_PREFIX = "decentralized_identifier:"
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
	}

	suspend fun getIssuerInformationFromSignedMetadata(
		metadata: CredentialIssuerMetadata.Signed,
		configuration: SwissTrustConfiguration = SwissTrustConfiguration(),
	): AgentInformation? {
		val host = Url(metadata.originalUrl).host
		val kid = getKidFromJwt(metadata.originalJwt) ?: return null
		val issuerDid = getDidFromAbsoluteKid(kid) ?: return null
		val did = trustService.getDidDocument(kid) ?: return null
		val verified = validateJwtWithDidDocument(metadata.originalJwt, did, false)
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

		// The client_id may be an HTTPS verifier URL. For Swiss Profile requests,
		// the signer DID is identified by the signed request JWT's kid.
		val request = originalRequest ?: return@withContext null
		val requestDid = signerDidFromJwt(request) ?: return@withContext null
		val clientIdDid = didFromClientId(presentationRequest.clientId)
		val presentationDidDoc = trustService.getDidDocument(requestDid)
		if (presentationDidDoc != null) {
			// A DID resolved from the request's kid is only bound to a DID client_id
			// by equality. HTTPS client_ids have no URL-to-DID relationship in the
			// Swiss profile, so the signer cannot be authorized for one here.
			val isTrusted = clientIdDid == requestDid &&
				validateJwtWithDidDocument(request, presentationDidDoc, true)
			var trustedIdentity: ValidatedStatement<IdentityTrustStatement>? = null
			for (statement in trustService.getTrustFromDid(requestDid, configuration)) {
				if (statementType(statement) != IDENTITY_TRUST_STATEMENT_TYPE) continue
				trustedIdentity = validateStatement(
					statement,
					IDENTITY_TRUST_STATEMENT_TYPE,
					requestDid,
					configuration,
				) {
					json.decodeFromString<IdentityTrustStatement>(it)
				}
				if (trustedIdentity != null) break
			}
			if (trustedIdentity != null) {
				return@withContext TrustData.Verification(
					baseUrl = baseUrl,
					identity = trustedIdentityFromStatement(trustedIdentity),
					identityJwt = trustedIdentity.jwt,
					verification = null,
					verificationJwt = null,
					isTrusted = isTrusted,
					isVerified = true
				)
			}
		}

		return@withContext null
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
		value.removePrefix(DECENTRALIZED_IDENTIFIER_PREFIX)

	private fun signerDidFromJwt(jwt: String): String? =
		getKidFromJwt(jwt)?.let(::getDidFromAbsoluteKid)

	private fun didFromClientId(clientId: String): String? =
		clientId
			.takeIf { it.startsWith(DECENTRALIZED_IDENTIFIER_PREFIX) }
			?.let(::normalizeDid)
			?.takeIf { it.startsWith("did:") }

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
			val issuer = getDidFromAbsoluteKid(header.kid) ?: return@runCatching null
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
		if (verifierInfo.isEmpty()) return null

		val types = verifierInfo.mapNotNull(::statementType)
		val hasSwissProfileRequest = presentationRequest.scope != null || types.any {
			it == IDENTITY_TRUST_STATEMENT_TYPE ||
				it == VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE ||
				it == PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE
		}
		if (!hasSwissProfileRequest) return null

		// Trust statements identify the verifier by DID. When a signed request is
		// available, derive that DID from the request key id and use it for every
		// subject/non-compliance decision. The client_id binding is checked
		// separately below; this prevents a signer from borrowing another
		// verifier's client_id.
		val clientIdDid = didFromClientId(presentationRequest.clientId) ?: return null
		val requestSignerDid = originalRequest?.let(::signerDidFromJwt)
		if (requestSignerDid != null && requestSignerDid != clientIdDid) return null
		val verifierDid = requestSignerDid ?: clientIdDid

		val identity = verifierInfo
			.filter { statementType(it) == IDENTITY_TRUST_STATEMENT_TYPE }
			.singleOrNull()
			?.let {
				validateStatement(it, IDENTITY_TRUST_STATEMENT_TYPE, verifierDid, configuration) {
					json.decodeFromString<IdentityTrustStatement>(it)
				}
			}
		val verificationQuery = verifierInfo
			.filter { statementType(it) == VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE }
			.singleOrNull()
			?.let {
				validateStatement(it, VERIFICATION_QUERY_PUBLIC_STATEMENT_TYPE, verifierDid, configuration) {
					json.decodeFromString<VerificationQueryPublicStatement>(it)
				}
			}
		val hasValidVerificationQuery = verificationQuery?.let {
			isVerificationQueryForRequest(it, presentationRequest)
		} == true

		val protectedAuthorizationStatements = verifierInfo
			.filter { statementType(it) == PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE }
			.mapNotNull {
				validateStatement(it, PROTECTED_VERIFICATION_AUTHORIZATION_STATEMENT_TYPE, verifierDid, configuration) {
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
				normalizeDid(actor.actor) == verifierDid
			}
		} == true

		val requestIntegrity = originalRequest?.let {
			validateSignedRequest(it, presentationRequest.clientId)
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
			// Resolve the signer from the key-bearing `kid`. An HTTPS client_id has
			// no verifiable relationship to a DID in this profile and therefore
			// cannot satisfy this binding.
			val requestDid = signerDidFromJwt(request) ?: return@runCatching false
			val clientDid = didFromClientId(clientId) ?: return@runCatching false
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

}
