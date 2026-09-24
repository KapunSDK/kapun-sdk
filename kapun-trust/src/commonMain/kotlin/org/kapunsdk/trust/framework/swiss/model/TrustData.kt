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

package org.kapunsdk.trust.framework.swiss.model

import kotlinx.serialization.Serializable

// TODO UBMW: Remove once we fully migrated to the new multi-trust framework approach
@Serializable
sealed interface TrustData {
	val baseUrl: String
	val identity: TrustedIdentity?
	val identityJwt: String?
	val isVerified: Boolean
	val isTrusted: Boolean

	@Serializable
	data class Issuance(
		val issuance: TrustedIssuance?,
		val issuanceJwt: String?,
		override val baseUrl: String,
		override val identity: TrustedIdentity?,
		override val identityJwt: String?,
		override val isTrusted: Boolean,
		override val isVerified: Boolean,
	) : TrustData

	@Serializable
	data class Verification(
		val verification: TrustedVerification?,
		val verificationJwt: String?,
		/** The Swiss Trust Protocol 2.0 Verification Query Public Statement. */
		val verificationQueryJwt: String? = null,
		/** Validated Protected Verification Authorization statements supplied by the verifier. */
		val protectedVerificationAuthorizationJwts: List<String> = emptyList(),
		/** Trust Protocol 2.0 markers established for this request. */
		val trustMarkers: List<String> = emptyList(),
		override val baseUrl: String,
		override val identity: TrustedIdentity?,
		override val identityJwt: String?,
		override val isTrusted: Boolean,
		override val isVerified: Boolean,
	) : TrustData

}
