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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import uniffi.kapun_crypto_rust.JweHeaderParameters
import uniffi.kapun_crypto_rust.JweKey
import uniffi.kapun_crypto_rust.decryptJwe as decryptJweRaw
import uniffi.kapun_crypto_rust.encryptJwe as encryptJweRaw
import uniffi.kapun_crypto_rust.generateJweKey as generateJweKeyRaw
import uniffi.kapun_crypto_rust.parseJweHeader as parseJweHeaderRaw
import uniffi.kapun_crypto_rust.publicJweJwk as publicJweJwkRaw

enum class JweKeyManagementAlgorithm(val identifier: String) {
	ECDH_ES("ECDH-ES"),
	ECDH_ES_A128KW("ECDH-ES+A128KW"),
	ECDH_ES_A192KW("ECDH-ES+A192KW"),
	ECDH_ES_A256KW("ECDH-ES+A256KW"),
	RSA_OAEP("RSA-OAEP"),
	RSA_OAEP_256("RSA-OAEP-256"),
}

enum class JweContentEncryptionAlgorithm(val identifier: String) {
	A128CBC_HS256("A128CBC-HS256"),
	A192CBC_HS384("A192CBC-HS384"),
	A256CBC_HS512("A256CBC-HS512"),
	A128GCM("A128GCM"),
	A192GCM("A192GCM"),
	A256GCM("A256GCM"),
}

enum class JweCompression(val identifier: String) {
	DEF("DEF"),
}

data class JweEncryptionOptions(
	val contentEncryption: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm.A256GCM,
	val agreementPartyUInfo: ByteArray? = null,
	val agreementPartyVInfo: ByteArray? = null,
	val tokenType: String? = null,
	val compression: JweCompression? = null,
)

fun generateJweKey(algorithm: JweKeyManagementAlgorithm): JweKey =
	generateJweKeyRaw(algorithm.identifier)

fun publicJweJwk(jwk: JsonObject): JsonObject =
	Json.parseToJsonElement(publicJweJwkRaw(jwk.toString())).jsonObject

fun parseJweHeader(compactJwe: String): JweHeaderParameters = parseJweHeaderRaw(compactJwe)

fun encryptJwe(
	jwk: JsonObject,
	payload: JsonObject,
	options: JweEncryptionOptions = JweEncryptionOptions(),
): String = encryptJweRaw(
	jwkJson = jwk.toString(),
	payloadJson = payload.toString(),
	contentEncryption = options.contentEncryption.identifier,
	apu = options.agreementPartyUInfo,
	apv = options.agreementPartyVInfo,
	tokenType = options.tokenType,
	compression = options.compression?.identifier,
)

fun decryptJwe(jwk: JsonObject, compactJwe: String): JsonObject =
	Json.parseToJsonElement(decryptJweRaw(jwk.toString(), compactJwe)).jsonObject
