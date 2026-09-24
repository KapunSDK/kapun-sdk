/* Copyright 2026 Ubique Innovation AG

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

package org.kapunsdk.presentation.request

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import uniffi.kapun_util_rust.Value
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class PresentationRequestTest {

	@Test
	fun parsesZkpIssuerMetadataFromAuthorizationRequest() {
		val request = Value.Object(
			mapOf(
				"client_id" to Value.String("https://verifier.example"),
				"zkp" to Value.Object(
					mapOf(
						"definition" to Value.String("definition"),
						"provingKey" to Value.String("proving-key"),
						"issuerPk" to Value.String("issuer-public-key"),
						"issuerId" to Value.String("did:example:issuer"),
						"issuerKeyId" to Value.String("did:example:issuer#key-1"),
					)
				),
			)
		)

		val zkp = assertNotNull(PresentationRequest.fromValue(request)?.zkp)

		assertEquals("definition", zkp.definition)
		assertEquals("proving-key", zkp.provingKey)
		assertEquals("issuer-public-key", zkp.issuerPk)
		assertEquals("did:example:issuer", zkp.issuerId)
		assertEquals("did:example:issuer#key-1", zkp.issuerKeyId)
	}

	@Test
	@OptIn(ExperimentalEncodingApi::class)
	fun resolvesScopedDcqlQueryFromVerifierInfo() {
		val query = """
			{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["https://example.com/identity"]}}]}
		""".trimIndent()
		val payload = """
			{"request":{"type":"DCQL","scope":"identity_presentation","query":$query},"purpose_name":"Identity","purpose_description":"Identity check"}
		""".trimIndent()
		fun encode(value: String): String = Base64.UrlSafe
			.withPadding(Base64.PaddingOption.ABSENT)
			.encode(value.encodeToByteArray())
		val vqPs = "${encode("{\"typ\":\"swiyu-verification-query-public-statement+jwt\"}")}.${encode(payload)}.signature"
		val request = Value.Object(
			mapOf(
				"client_id" to Value.String("did:example:verifier"),
				"scope" to Value.String("identity_presentation"),
				"verifier_info" to Value.Array(
					listOf(
						Value.Object(
							mapOf(
								"format" to Value.String("jwt"),
								"data" to Value.String(vqPs),
							)
						)
					)
				),
			)
		)

		val parsed = assertNotNull(PresentationRequest.fromValue(request))

		assertEquals("identity_presentation", parsed.scope)
		assertNotNull(parsed.dcqlQuery)
	}
}
