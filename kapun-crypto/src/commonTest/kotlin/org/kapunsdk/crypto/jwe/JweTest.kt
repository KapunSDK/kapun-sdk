/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.kapunsdk.crypto.jwe

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

class JweTest {
	@Test
	fun kotlinFacadeRoundTrip() {
		val key = generateJweKey(JweKeyManagementAlgorithm.ECDH_ES_A256KW)
		val publicKey = Json.parseToJsonElement(key.publicJwk).jsonObject
		val privateKey = Json.parseToJsonElement(key.privateJwk).jsonObject
		val payload = buildJsonObject {
			put("credential", JsonPrimitive("example"))
		}

		val compactJwe = encryptJwe(
			jwk = publicKey,
			payload = payload,
			options = JweEncryptionOptions(compression = JweCompression.DEF),
		)

		assertEquals("ECDH-ES+A256KW", parseJweHeader(compactJwe).algorithm)
		assertEquals(payload, decryptJwe(privateKey, compactJwe))
	}
}
