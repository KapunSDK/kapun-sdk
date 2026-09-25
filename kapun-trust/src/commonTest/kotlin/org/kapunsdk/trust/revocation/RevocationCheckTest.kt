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

package org.kapunsdk.trust.revocation

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import uniffi.kapun_crypto_rust.base64UrlEncode

class RevocationCheckTest {
	@Test
	fun readsIssuerFromStatusListHeaderKid() {
		val header = base64UrlEncode(
			"{\"kid\":\"decentralized_identifier:did:webvh:issuer#status-list-key\"}"
				.encodeToByteArray()
		)
		val payload = base64UrlEncode("{}".encodeToByteArray())

		assertEquals(
			"did:webvh:issuer",
			extractStatusListIssuer("$header.$payload.signature", Json.Default),
		)
	}
}
