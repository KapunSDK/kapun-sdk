/* Copyright 2025 Ubique Innovation AG

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

package org.kapunsdk

import org.kapunsdk.credentials.Bbs
import org.kapunsdk.credentials.Bbs.Companion.BBS_TERMWISE_FORMATS
import org.kapunsdk.credentials.SdJwtErrors
import org.kapunsdk.util.extensions.asObject
import org.kapunsdk.util.extensions.get
import uniffi.kapun_dcql_bbs_rust.BbsRust
import uniffi.kapun_dcql_bbs_rust.BbsWrapper
import uniffi.kapun_dcql_bbs_rust.ClaimBasedParams
import uniffi.kapun_dcql_bbs_rust.DeviceBindingType
import uniffi.kapun_credential_core_rust.PointerPart
import uniffi.kapun_credential_core_rust.Selector
import uniffi.kapun_dcql_bbs_rust.bbsDeriveClaimBasedProof
import uniffi.kapun_dcql_bbs_rust.bbsGetBody
import uniffi.kapun_dcql_bbs_rust.decodeBbs
import uniffi.kapun_dcql_rust.CombinedBbsMetaMismatch
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.CredentialLike
import uniffi.kapun_dcql_rust.CredentialParser
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_dcql_rust.Meta
import uniffi.kapun_dcql_rust.MetaMismatch
import uniffi.kapun_dcql_rust.registerParser
import uniffi.kapun_util_rust.Value
import kotlin.text.iterator

sealed interface BbsErrors {
    data object InvalidCredentialBodyType : BbsErrors, Throwable("Invalid credential body type")

    data class UnsatisfiableClaim(
        val key: String
    ) : BbsErrors, Throwable("Expected a claim with name: $key")

    data class UnsatisfiableClaimValue(
        val key: String,
        val value: String,
        val values: List<String>
    ) : BbsErrors, Throwable("$key = $value, but expected one of $values")

    data object UnsatisfiableCredentialQuery : BbsErrors,
        Throwable("The credential query couldn't be satisfied")
}

object BbsParser: CredentialParser {
    init {
        register()
    }

    fun register() = registerParser(this)

    override fun id(): String {
        return "BBS-PARSER"
    }

    override fun fromStr(credential: String): Credential? {
        return runCatching {
            val bbs = decodeBbs(credential)
            return Credential.BbsCredential(BbsCredential(BbsWrapper.fromBbs(bbs)))
        }.getOrNull()
    }

}

class BbsCredential(val bbs: BbsWrapper) : CredentialLike {
    override fun getBody(): Value {
       return bbs.body()
    }
    override fun serialize(): String {
        return bbs.getBbs().originalBbs
    }

    override fun formatSpecifiers(): List<String> {
        return listOf("bbs-termwise")
    }

    override fun matchesMeta(meta: Meta?): MetaMismatch? {
        return when(meta) {
		   is Meta.W3c -> {
               val bbsTypes = bbs.types()
               return if(!meta.credentialTypes.any { bbsTypes.contains(it) }) {
                   MetaMismatch.BbsMetaMismatch(CombinedBbsMetaMismatch.WRONG_CREDENTIAL_TYPE)
               } else {
                   null
               }
           }
            else if meta == null -> null
            else -> MetaMismatch.BbsMetaMismatch(CombinedBbsMetaMismatch.INVALID_META)
	   }
    }
    override fun get(selector: Selector): List<Value>? {
        return runCatching { bbs.get(selector) }.getOrNull()
    }
}


fun BbsRust.body() : Value {
    return bbsGetBody(this)
}

fun Bbs.getVpToken(
    query: CredentialQuery,
    issuerPk: String,
    issuerId: String,
    issuerKeyId: String,
    deviceBindingPk: ByteArray?,
    message: ByteArray,
    messageSignature: ByteArray?,
    clientId: String,
    nonce: String,
    deviceBindingType: DeviceBindingType,
): Result<String> {
    if (!BBS_TERMWISE_FORMATS.contains(query.format)) {
        return Result.failure(SdJwtErrors.InvalidFormat(query.format))
    }

    val claims = this.inner.body().asObject()
        ?: return Result.failure(BbsErrors.InvalidCredentialBodyType)

    val builder = this.presentation(issuerPk, issuerId, issuerKeyId)

    // Add device binding
    if (messageSignature != null && deviceBindingPk != null) {
        builder.setDeviceBinding(
            uncompressedPublicKey = deviceBindingPk,
            message = message,
            signature = messageSignature,
            commKeySecpLabel = "$clientId-$nonce-secp".encodeToByteArray(),
            commKeyTomLabel = "$clientId-$nonce-tom".encodeToByteArray(),
            commKeyBlsLabel = "$clientId-$nonce-bls".encodeToByteArray(),
            bppSetupLabel = "$clientId-$nonce-bpp".encodeToByteArray(),
            type = deviceBindingType
        )
    }

    // If claims is absent, no selectively disclosable claims are requested. Treat an empty legacy
    // value the same way so that invalid input fails closed instead of disclosing data.
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
    if (query.claims.isNullOrEmpty()) {
        return runCatching { builder.buildWithStacksize(8388608U) }
    }

    val requestedClaims = query.claims.orEmpty()
    val requestedClaimSets = query.claimSets
    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims
    if (requestedClaimSets == null) {
        for (claim in requestedClaims) {
            // TODO: Add support for nested paths
            val key = (claim.path[0] as PointerPart.String).v1

            if (!claims.keys.contains(key)) {
                return Result.failure(BbsErrors.UnsatisfiableClaim(key))
            }

            val allowedValues = claim.values
            if (allowedValues != null && !allowedValues.contains(claims[key])) {
                return Result.failure(
                    BbsErrors.UnsatisfiableClaimValue(
                        key,
                        claims[key].toString(),
                        allowedValues.map { it.toString() })
                )
            }

            builder.addDisclosure(key)
        }
        return runCatching { builder.buildWithStacksize(8388608U) }
    }

    // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets.
    // The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
    // the Wallet MUST return the first option that it can satisfy.
    // If the Wallet cannot satisfy any of the options, it MUST NOT return any claims
    setLoop@ for (option in requestedClaimSets) {
        var disclosures = mutableListOf<String>()
        for (claim in option) {
            val claimQuery = requestedClaims.firstOrNull {
                it.id == claim
            } ?: continue@setLoop

            // TODO: Add support for nested paths
            val key = (claimQuery.path[0] as PointerPart.String).v1

            if (!claims.keys.contains(key)) {
                continue@setLoop
            }

            val allowedValues = claimQuery.values
            if (allowedValues != null && !allowedValues.contains(claims[key])) {
                continue@setLoop
            }

            disclosures.add(key)
        }

        // we passed all options, so lets add them to the token and return
        for (key in disclosures) {
            builder.addDisclosure(key)
        }
        return runCatching { builder.buildWithStacksize(8388608U) }
    }

    return Result.failure(BbsErrors.UnsatisfiableCredentialQuery)
}

fun bbsCombinedClaimBasedProof(
    vc1: Bbs,
    q1: CredentialQuery,

    deviceBindingPk: ByteArray,
    message: ByteArray,
    messageSignature: ByteArray,
    clientId: String,
    nonce: String,
    deviceBindingType: DeviceBindingType,

    vc2: Bbs,
    q2: CredentialQuery,

    issuerPk: String,
    issuerId: String,
    issuerKeyId: String,
): Result<String> {
    val vc1Body = vc1.body()
    val claims1 = DcqlClaimQueryResolver.neededClaims(q1, { path, values ->
        val key = (path.first() as? PointerPart.String)?.v1 ?: return@neededClaims false
        val value = vc1Body[key]
        values?.contains(value) ?: true
    }) ?: return Result.failure(Exception("VC1 doesn't satisfy Q1"))

    val vc2Body = vc2.body()
    val claims2 = DcqlClaimQueryResolver.neededClaims(q2, { path, values ->
        val key = (path.first() as? PointerPart.String)?.v1 ?: return@neededClaims false
        val value = vc2Body[key]
        values?.contains(value) ?: true
    }) ?: return Result.failure(Exception("VC2 doesn't satisfy Q2"))

    val dis1 = claims1.map { (it.path.first() as PointerPart.String).v1 }
    val dis2 = claims2.map { (it.path.first() as PointerPart.String).v1 }

    val common = dis1.intersect(dis2).toList()

    return runCatching {
        bbsDeriveClaimBasedProof(ClaimBasedParams(
            vc1 = vc1.inner,
            dis1 = dis1 - common,
            uncompressedPublicKey = deviceBindingPk,
            message = message,
            signature = messageSignature,
            commKeySecpLabel = "$clientId-$nonce-secp".encodeToByteArray(),
            commKeyTomLabel = "$clientId-$nonce-tom".encodeToByteArray(),
            commKeyBlsLabel = "$clientId-$nonce-bls".encodeToByteArray(),
            bppSetupLabel = "$clientId-$nonce-bpp".encodeToByteArray(),
            vc2 = vc2.inner,
            dis2 = dis2 - common,
            common = common,
            issuerPk = issuerPk,
            issuerId = issuerId,
            issuerKeyId = issuerKeyId,
            deviceBindingType = deviceBindingType,
            stackSize = 8U * 1024U * 1024U,
        ))
    }
}
