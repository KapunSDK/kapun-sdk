package org.kapunsdk.trust.framework.oidcfederation

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadata
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.framework.DocumentProvider
import org.kapunsdk.trust.framework.OidfTrustAnchorProvider
import org.kapunsdk.trust.framework.TrustFramework
import org.kapunsdk.trust.framework.ValidationInfo
import org.kapunsdk.trust.model.AgentInformation
import org.kapunsdk.trust.model.AgentType
import org.kapunsdk.trust.model.TrustAnchorInfo
import org.kapunsdk.util.log.Logger
import uniffi.kapun_trust_rust.FederationException
import uniffi.kapun_trust_rust.oidcfTrustChainFromPresentationRequest
import uniffi.kapun_trust_rust.oidcfTrustChainFromUrl
import kotlin.io.encoding.Base64

const val OIDC_FEDERATION_TRUST_FRAMEWORK_ID: String = "oidc_federation_framework"

class OidcFederationTrustFramerwork(
	val documentProvider: DocumentProvider? = null,
	val oidfTrustAnchorProvider: OidfTrustAnchorProvider = StaticOidfTrustAnchorProvider(),
	private val lenientTrustChainVerification: () -> Boolean = { false },
	private val httpClient: HttpClient? = null,
) : TrustFramework {
	override val frameworkId: String
		get() = OIDC_FEDERATION_TRUST_FRAMEWORK_ID


	override suspend fun getIssuerInformation(
		baseUrl: String,
		credentialConfigurationIds: List<String>,
		credentialIssuerMetadata: CredentialIssuerMetadata
	): AgentInformation? {
		// TODO: get credentialIssuerMetadata from here instead of fetching it earlier.
		val trustInfo = try {
			oidcfTrustChainFromUrl(
				credentialIssuerMetadata.claims.credentialIssuer,
				lenientTrustChainVerification(),
			);
		} catch (e: FederationException) {
			Logger("Federation").error("Federation failed, skipping it", e)
			return null
		}

		val invalidTrustAnchors = trustInfo.trustAnchorKeys.filterNot {
			val isTrusted = oidfTrustAnchorProvider.isTrusted(it)
			if (!isTrusted) {
				oidfTrustAnchorProvider.onInvalidTrustAnchor(it)
			}
			isTrusted
		}
		val isTrusted = invalidTrustAnchors.size < trustInfo.trustAnchorKeys.size
		val isVerified = credentialConfigurationIds.all {
			trustInfo.leaf.credentialConfigurationsSupported?.contains(it) ?: false
		};

		return AgentInformation(
			type = AgentType.ISSUER,
			domain = trustInfo.leaf.domain,
			displayName = trustInfo.leaf.displayName,
			trustFrameworkId = OIDC_FEDERATION_TRUST_FRAMEWORK_ID,
			logoUri = downloadLogo(trustInfo.leaf.logoUri),
			isTrusted = isTrusted,
			isVerified = isVerified,
			identityTrust = null,
			issuanceTrust = trustInfo.subordinateStatements.joinToString(separator = "\n"),
			verificationTrust = null,
			untrustedTrustAnchor = invalidTrustAnchors.firstOrNull()?.toTrustAnchorInfo(),
		)
	}

	override suspend fun getVerifierInformation(
		requestUri: String, presentationRequest: PresentationRequest, originalRequest: String?
	): AgentInformation? {
		if (originalRequest == null) {
			return null
		}
		val trustInfo = try {
			oidcfTrustChainFromPresentationRequest(
				originalRequest!!,
				lenientTrustChainVerification(),
			);
		} catch (e: FederationException.FetchingFailed) {
			return null
		}

		val invalidTrustAnchors = trustInfo.trustAnchorKeys.filterNot {
			val isTrusted = oidfTrustAnchorProvider.isTrusted(it)
			if (!isTrusted) {
				oidfTrustAnchorProvider.onInvalidTrustAnchor(it)
			}
			isTrusted
		}
		val isTrusted = invalidTrustAnchors.size < trustInfo.trustAnchorKeys.size
		val isVerified = true;

		return AgentInformation(
			type = AgentType.VERIFIER,
			domain = trustInfo.leaf.domain,
			displayName = trustInfo.leaf.displayName,
			trustFrameworkId = OIDC_FEDERATION_TRUST_FRAMEWORK_ID,
			logoUri = downloadLogo(trustInfo.leaf.logoUri),
			isTrusted = isTrusted,
			isVerified = isVerified,
			identityTrust = null,
			issuanceTrust = null,
			verificationTrust = trustInfo.subordinateStatements.joinToString(separator = "\n"),
			untrustedTrustAnchor = invalidTrustAnchors.firstOrNull()?.toTrustAnchorInfo(),
		);
	}

	override fun saveTrustAnchor(trustAnchor: TrustAnchorInfo) {
		if (trustAnchor.trustFrameworkId != frameworkId) {
			return
		}
		oidfTrustAnchorProvider.addTrustAnchor(
			uniffi.kapun_trust_rust.TrustAnchor(trustAnchor.key, trustAnchor.subject)
		)
	}

	override fun getTrustAnchors(): List<TrustAnchorInfo> {
		val userTrustAnchors = oidfTrustAnchorProvider.getUserTrustAnchors().toSet()
		return oidfTrustAnchorProvider.getTrustAnchors()
			.distinct()
			.map { it.toTrustAnchorInfo(isRemovable = it in userTrustAnchors) }
	}

	override fun removeTrustAnchor(trustAnchor: TrustAnchorInfo) {
		if (trustAnchor.trustFrameworkId != frameworkId || !trustAnchor.isRemovable) {
			return
		}
		oidfTrustAnchorProvider.removeTrustAnchor(
			uniffi.kapun_trust_rust.TrustAnchor(trustAnchor.key, trustAnchor.subject)
		)
	}

	private fun uniffi.kapun_trust_rust.TrustAnchor.toTrustAnchorInfo(
		isRemovable: Boolean = true,
	) = TrustAnchorInfo(
		key = key,
		subject = sub,
		trustFrameworkId = OIDC_FEDERATION_TRUST_FRAMEWORK_ID,
		isRemovable = isRemovable,
	)

	private suspend fun downloadLogo(logoUri: String?): String? {
		if (logoUri == null || logoUri.startsWith("data:")) {
			return logoUri
		}
		val client = httpClient ?: return logoUri

		return runCatching {
			val response = client.get(logoUri)
			val contentType = response.headers[io.ktor.http.HttpHeaders.ContentType]
				?.substringBefore(';')
				?.takeIf { it.startsWith("image/") }
				?: return@runCatching logoUri
			val data = response.body<ByteArray>()
			"data:$contentType;base64,${Base64.encode(data)}"
		}.getOrDefault(logoUri)
	}


	override suspend fun validatePresentationRequest(presentationRequest: PresentationRequest): ValidationInfo {
		// No concept of semantic correctness of a presentation request in this trust framework.
		return ValidationInfo(isValid = true)
	}

	override suspend fun getAllowedDocuments(
		presentationRequest: PresentationRequest,
		includeUsedCredentials: Boolean,
	): List<CredentialModel> {
		// No concept of filtering credentials based on presentation request in this trust framework.
		return documentProvider?.getAllCredentials().orEmpty();
	}
}
