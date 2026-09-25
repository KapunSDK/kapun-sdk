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

package org.kapunsdk.trust

import io.ktor.client.HttpClient
import kotlin.test.Test
import kotlin.test.assertEquals
import org.kapunsdk.trust.framework.swiss.SwissTrustService

class SwissTrustConfigurationTest {
	@Test
	fun derivesTrustRegistryBaseUrlFromSwissTrustIssuerDid() {
		val httpClient = HttpClient()
		try {
			val service = SwissTrustService(httpClient)
			assertEquals(
				"https://trust-reg.trust-infra.swiyu-int.admin.ch",
				service.deriveTrustStatementApiBaseUrl(
					"did:webvh:integrity:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:issuer"
				),
			)
		} finally {
			httpClient.close()
		}
	}
}
