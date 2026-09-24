/* Copyright 2025 Ubique Innovation AG

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

@file:OptIn(kotlin.time.ExperimentalTime::class)

package org.kapunsdk.trust.framework.swiss.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_dcql_rust.DcqlQuery
import uniffi.kapun_dcql_rust.Meta
import kotlin.time.Instant

@Serializable
internal data class TrustStatementHeader(
	val typ: String,
	val alg: String,
	val kid: String,
	@SerialName("profile_version") val profileVersion: String,
)

/** Common payload fields shared by Swiss Profile Trust statements. */
internal interface TrustStatementPayload {
	val jti: String
	val sub: String?
	val iat: Long
	val nbf: Long?
	val exp: Long
	val status: TrustStatementStatus?
}

@Serializable
internal data class TrustStatementStatus(
	@SerialName("status_list") val statusList: TrustStatusList,
)

@Serializable
internal data class TrustStatusList(
	val idx: Long,
	val uri: String,
) {
	init {
		require(idx in 0..Int.MAX_VALUE.toLong())
		require(uri.isNotBlank())
	}
}

@Serializable
internal data class IdentityTrustStatement(
	override val jti: String,
	override val sub: String?,
	override val iat: Long,
	override val nbf: Long? = null,
	override val exp: Long,
	override val status: TrustStatementStatus?,
	val vct: String? = null,
	val iss: String? = null,
	@SerialName("entity_name") val entityName: String,
	@SerialName("is_state_actor") val isStateActor: Boolean,
	@SerialName("registry_ids") val registryIds: List<Registry>? = null,
	@SerialName("logo_uri") val logoUri: String? = null,
	@SerialName("pref_lang") val prefLang: String? = null,
) : TrustStatementPayload {
	init {
		require(sub?.isNotBlank() == true)
		require(status != null)
		require(entityName.isNotBlank())
	}
}

@Serializable
internal data class VerificationQueryPublicStatement(
	override val jti: String,
	override val sub: String?,
	override val iat: Long,
	override val nbf: Long? = null,
	override val exp: Long,
	override val status: TrustStatementStatus? = null,
	@SerialName("purpose_name") val purposeName: String,
	@SerialName("purpose_description") val purposeDescription: String,
	val request: VerificationQueryRequest,
) : TrustStatementPayload {
	init {
		require(sub?.isNotBlank() == true)
		require(purposeName.isNotBlank())
		require(purposeDescription.isNotBlank())
		require(purposeName.length <= 40)
		require(purposeDescription.length <= 1_000)
	}
}

@Serializable
internal data class VerificationQueryRequest(
	val type: String,
	val scope: String,
	val query: DcqlQuery,
) {
	init {
		require(type == "DCQL")
		require(scope.isNotBlank())
		val credentials = query.credentials.orEmpty()
		require(credentials.isNotEmpty())
		require(credentials.all(CredentialQuery::hasNonEmptyVctValues))
	}
}

private fun CredentialQuery.hasNonEmptyVctValues(): Boolean = when (val credentialMeta = meta) {
	is Meta.SdjwtVc -> credentialMeta.vctValues.isNotEmpty() &&
		credentialMeta.vctValues.all(String::isNotBlank)
	else -> false
}

@Serializable
internal data class ProtectedVerificationAuthorizationTrustStatement(
	override val jti: String,
	override val sub: String?,
	override val iat: Long,
	override val nbf: Long? = null,
	override val exp: Long,
	override val status: TrustStatementStatus?,
	@SerialName("authorized_fields") val authorizedFields: List<String>,
) : TrustStatementPayload {
	init {
		require(sub?.isNotBlank() == true)
		require(status != null)
		require(authorizedFields.isNotEmpty())
		require(authorizedFields.all(String::isNotBlank))
	}
}

@Serializable
internal data class NonComplianceTrustListStatement(
	override val jti: String,
	override val sub: String? = null,
	override val iat: Long,
	override val nbf: Long? = null,
	override val exp: Long,
	override val status: TrustStatementStatus?,
	@SerialName("non_compliant_actors") val nonCompliantActors: List<NonCompliantActor>,
) : TrustStatementPayload {
	init {
		require(status != null)
	}
}

@Serializable
internal data class NonCompliantActor(
	val actor: String,
	@SerialName("flagged_at") val flaggedAt: String,
	val reason: String,
) {
	init {
		require(actor.isNotBlank())
		require(runCatching { Instant.parse(flaggedAt) }.isSuccess)
		require(reason.isNotBlank())
	}
}
