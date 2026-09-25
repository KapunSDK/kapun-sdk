package org.kapunsdk.crypto.jwt

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.json
import uniffi.kapun_crypto_rust.GenericJwtVerifier
import uniffi.kapun_crypto_rust.parseEncodedJwtHeader
import uniffi.kapun_crypto_rust.parseEncodedJwtPayload
import uniffi.kapun_crypto_rust.validateJwtWithJwkAndValidator
import uniffi.kapun_crypto_rust.JwtValidator as RustValidator
import uniffi.kapun_util_rust.Value

data class JwtValidator(val requiredClaims: Map<String, Value>? = null) : RustValidator {
	override fun validateBody(body: Value): Boolean {
		if(requiredClaims == null) {
			return true
		}
		for(entry in requiredClaims) {
			val a = body[entry.key]
			if(a != entry.value) {
				return false
			}
		}
		return true
	}

	override fun validateHeader(header: Value): Boolean {
		return true
	}
}

class Jwt(private val jwt: String, private val validator: JwtValidator, private val validityAt: Long? = null){
	fun getHeader() : JsonElement {
		val h = parseEncodedJwtHeader(jwt) ?: return JsonNull
		val o = runCatching { json.parseToJsonElement(h) }.getOrNull() ?: return JsonNull
		return o
	}
	fun insecureGetPayload() : JsonElement {
		val p = parseEncodedJwtPayload(jwt) ?: return JsonNull
		val o = runCatching { json.parseToJsonElement(p) }.getOrNull() ?: return JsonNull
		return o
	}
	fun validateJwt(jwk: Value) : Boolean {
		val validator = GenericJwtVerifier(jwtValidator = validator, timeOfValidity = validityAt)
		return validateJwtWithJwkAndValidator(jwt, jwk, validator)
	}
	fun validateJwtWithType(type: String, jwk: Value) : Boolean {
		val validator = GenericJwtVerifier(ty = type,jwtValidator = validator, timeOfValidity = validityAt)
		return validateJwtWithJwkAndValidator(jwt, jwk, validator)
	}
}