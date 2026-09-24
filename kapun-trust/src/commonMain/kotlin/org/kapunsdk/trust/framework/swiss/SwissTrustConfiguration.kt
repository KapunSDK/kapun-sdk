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

package org.kapunsdk.trust.framework.swiss

/**
 * Environment-specific trust anchors for the Swiss Profile Trust.
 *
 * The defaults are the Swiss Profile Trust environment currently published by swiyu. Custom
 * environments must configure both their trust-statement issuers and trust-registry base URLs.
 */
data class SwissTrustConfiguration(
	val trustedStatementIssuers: List<String> = listOf(
		"did:webvh:QmdVPcfEJgvQAJKEjaTWAhskT1kc59KZQiXNenqHBB7iH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:4c131dc4-ced1-454b-bbd4-9401c7512e37",
		"did:webvh:QmNTHuhETA3u2ypoujoaEMaZGKf5HpPwkV6ktfgzu7JzMp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:5e5de412-0e7d-4982-a0ed-bd55a0f25a04",
	),
	val trustStatementApiBaseUrls: List<String> = listOf(
		"https://trust-reg.trust-infra.swiyu-int.admin.ch",
	),
) {
	init {
		require(trustedStatementIssuers.isNotEmpty())
		require(trustedStatementIssuers.all { it.trim().startsWith("did:") })
		require(trustStatementApiBaseUrls.isNotEmpty())
		require(trustStatementApiBaseUrls.all { it.trim().startsWith("https://") })
	}
}

internal fun SwissTrustConfiguration.allowsStatementIssuer(issuer: String): Boolean =
	trustedStatementIssuers.any {
		it.trim().removePrefix("decentralized_identifier:").substringBefore('#') == issuer
	}

internal fun SwissTrustConfiguration.allowsApiBaseUrl(apiBaseUrl: String): Boolean =
	trustStatementApiBaseUrls.any { it.trim().trimEnd('/') == apiBaseUrl.trimEnd('/') }
