/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package org.kapunsdk

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import org.kapunsdk.credentials.SdJwt
import org.kapunsdk.credentials.toClaimsPointer
import uniffi.kapun_credential_core_rust.SignatureCreator
import uniffi.kapun_dcql_w3c_rust.parseW3cSdJwt
import uniffi.kapun_util_rust.Value

class ClaimRegistrationTest {
	private val signer = object : SignatureCreator {
		override fun alg(): String = "ES256"

		override fun sign(bytes: ByteArray): ByteArray = byteArrayOf(1, 2, 3)
	}

	private fun issueW3cSdJwt(claimName: String): String {
		val credential = SdJwt.create(
			claims = Value.Object(
				mapOf(
					"type" to Value.Array(
						listOf(Value.String("VerifiableCredential"), Value.String("TestCredential")),
					),
					claimName to Value.String("test-value"),
				),
			),
			disclosures = listOf(listOf(claimName).toClaimsPointer()!!),
			keyId = "test-key",
			key = signer,
			pubKeyJwk = null,
		)
		return assertNotNull(credential).innerJwt.originalSdjwt
	}

	@Test
	fun w3cParserUsesItsRegisteredIllegalAndUndisclosableClaims() {
		registerInvalidAndUndisclosableClaims()
		try {
			val undisclosableJwt = issueW3cSdJwt("custom_secret")
			val illegalJwt = issueW3cSdJwt("reserved_custom_claim")
			val ordinaryJwt = issueW3cSdJwt("ordinary_claim")

			parseW3cSdJwt(undisclosableJwt)
			parseW3cSdJwt(illegalJwt)
			parseW3cSdJwt(ordinaryJwt)

			registerInvalidAndUndisclosableClaims(
				illegalClaims = listOf("reserved_custom_claim"),
				undisclosableClaims = listOf("custom_secret"),
			)
			assertFailsWith<Throwable> { parseW3cSdJwt(undisclosableJwt) }
			assertFailsWith<Throwable> { parseW3cSdJwt(illegalJwt) }
			parseW3cSdJwt(ordinaryJwt)
		} finally {
			registerInvalidAndUndisclosableClaims()
		}
	}
}
