package org.kapunsdk.trustedAuthority

import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.get
import uniffi.kapun_credentials_rust.decodeSdjwt
import uniffi.kapun_crypto_rust.getKidFromJwt
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.TrustedAuthority
import uniffi.kapun_dcql_rust.TrustedAuthorityMatcher
import uniffi.kapun_dcql_rust.TrustedAuthorityQueryType
import uniffi.kapun_dcql_rust.registerMatcher

object DidAuthorityMatcher : TrustedAuthorityMatcher {
	fun register() {
		registerMatcher(this)
	}

	override fun id(): String = "DidSdJwtAuthorityMatcher"

	override fun matches(value: Credential, trustedAuthority: TrustedAuthority): Boolean? {
		return when (value) {
			is Credential.SdJwtCredential -> {
				val jwt = decodeSdjwt(value.v1.serialize())
				val kid = getKidFromJwt(jwt.originalJwt)
				val did = kid?.split("#")?.firstOrNull()
				val issuer = jwt.claims["iss"].asString() ?: did ?: return false
				trustedAuthority.values.contains(issuer)
			}
			else -> null
		}
	}

	override fun queryType(): TrustedAuthorityQueryType = TrustedAuthorityQueryType.DECENTRALIZED_IDENTIFIER
}
