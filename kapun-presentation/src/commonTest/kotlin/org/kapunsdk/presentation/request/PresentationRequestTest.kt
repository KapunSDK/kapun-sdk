/* Copyright 2026 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

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
}
