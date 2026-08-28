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

import org.kapunsdk.credentials.Mdoc
import org.kapunsdk.credentials.Mdoc.Companion.MDOC_FORMATS
import org.kapunsdk.credentials.SdJwtErrors
import org.kapunsdk.credentials.get
import org.kapunsdk.credentials.toClaimsPointer
import org.kapunsdk.util.extensions.asArray
import org.kapunsdk.util.extensions.asBytes
import org.kapunsdk.util.extensions.asObject
import org.kapunsdk.util.extensions.asOrderedObject
import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.asTag
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.isSame
import org.kapunsdk.util.extensions.toCbor
import kotlinx.serialization.json.Json
import uniffi.kapun_dcql_mdoc_rust.MdocRust
import uniffi.kapun_credential_core_rust.PointerPart
import uniffi.kapun_credential_core_rust.Selector
import uniffi.kapun_credential_core_rust.SignatureCreator
import uniffi.kapun_dcql_mdoc_rust.decodeMdoc
import uniffi.kapun_crypto_rust.base64UrlEncode
import uniffi.kapun_dcql_rust.CombinedMdocMetaMismatch
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.CredentialLike
import uniffi.kapun_dcql_rust.CredentialParser
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_dcql_rust.Meta
import uniffi.kapun_dcql_rust.MetaMismatch
import uniffi.kapun_dcql_rust.registerParser
import uniffi.kapun_util_rust.Value
import uniffi.kapun_util_rust.decodeCbor
import uniffi.kapun_util_rust.encodeCbor
import kotlin.collections.iterator
import kotlin.text.iterator

object MdocParser: CredentialParser {
    init {
        register()
    }
    fun register() = registerParser(this)
    override fun id(): String {
        return "mdoc-parser"
    }

    override fun fromStr(credential: String): Credential? {
        return runCatching { decodeMdoc(credential) }.getOrNull()?.let {
            Credential.MdocCredential(MdocCredential(it))
        }
    }
}

class MdocCredential(val mdoc: MdocRust) : CredentialLike {
    override fun getBody(): Value {
        return mdoc.namespaceMap
    }

    override fun serialize(): String {
        return mdoc.originalMdoc
    }

    override fun formatSpecifiers(): List<String> {
       return listOf("mso_mdoc")
    }

    override fun matchesMeta(meta: Meta?): MetaMismatch? {
       return when(meta){
		   is Meta.IsoMdoc -> {
               val docType = docType() ?: return MetaMismatch.MdocMetaMismatch(CombinedMdocMetaMismatch.WRONG_DOC_TYPE)
               return if(docType != meta.doctypeValue) {
                   MetaMismatch.MdocMetaMismatch(CombinedMdocMetaMismatch.WRONG_DOC_TYPE)
               } else {
                   null
               }
           }
		   null -> null
           else -> MetaMismatch.MdocMetaMismatch(CombinedMdocMetaMismatch.INVALID_META)
	   }
    }

    override fun get(selector: Selector): List<Value>? {
		return runCatching { mdoc.namespaceMap[selector] }.getOrNull()
    }
    fun docType() : String? {
        val result = this.mdoc.issuerAuth[listOf("docType").toClaimsPointer()!!]
        if (result.size != 1) {
            return null
        }
        return result[0].asString()
    }
}


fun Mdoc.getVpToken(
    query: CredentialQuery,
    clientId: String,
    responseUri: String,
    nonce: String,
    jwkThumbprint: ByteArray?,
    signer: SignatureCreator,
): Result<String> {
    if (!MDOC_FORMATS.contains(query.format)) {
        return Result.failure(SdJwtErrors.InvalidFormat(query.format))
    }
    val sessionTranscript = this.getSessionTranscript(
        clientId = clientId,
        nonce = nonce,
        jwkThumbprint = jwkThumbprint,
        responseUri = responseUri,
    )
    var issuerSigned = this.mdoc.originalDecoded
    val originalIssuerAuth = issuerSigned.get("issuerAuth")

    // If claims is absent, no selectively disclosable claims are requested. Treat an empty legacy
    // value the same way so that invalid input fails closed instead of disclosing data.
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
    if (query.claims.isNullOrEmpty()) {
        issuerSigned = mapOf(
            "issuerAuth" to originalIssuerAuth,
            "nameSpaces" to emptyMap<String, Value>()
        ).toCbor()
        return Result.success(
            base64UrlEncode(
                encodeCbor(this.buildToken(signer, issuerSigned, sessionTranscript))
            )
        )
    }
    val namespaces = mutableMapOf<String, MutableList<Value>>()
    val requestedClaims = query.claims.orEmpty()
    val requestedClaimSets = query.claimSets
    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims
    if (requestedClaimSets == null) {
        for (claim in requestedClaims) {
            val namespace = (claim.path[0] as PointerPart.String).v1
            val claimName = (claim.path[1] as PointerPart.String).v1

            val theNamespace = this.mdoc.originalDecoded["nameSpaces"][namespace]
            if (theNamespace == Value.Null) {
                return Result.failure(InvalidClaimsQuery(claim))
            }
            val pair = theNamespace.asArray()!!
                .map{ value ->
                    Pair(value, decodeCbor(value.asTag()!!.value[0].asBytes()!!))
                }.first { it.second["elementIdentifier"].asString()!! == claimName }
            val element = pair.second
            if (element.isSame(Value.Null)) {
                return Result.failure(InvalidClaimsQuery(claim))
            }
            // Ensure the value matches the predicates
            val allowedValues = claim.values
            if (allowedValues != null) {
                if (!allowedValues.any { it.isSame(element["elementValue"]) }) {
                    return Result.failure(InvalidClaimsQuery(claim))
                }
            }
            val namespaceElements = namespaces.getOrPut(namespace) { mutableListOf() }
            namespaceElements.add(pair.first.toCbor())
        }
    } else {
        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets.
        // The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet MUST return the first option that it can satisfy.
        // If the Wallet cannot satisfy any of the options, it MUST NOT return any claims
        setLoop@ for (option in requestedClaimSets) {
            var disclosurePtrs = mutableMapOf<String, MutableList<Value>>()
            for (claim in option) {
                val claimQuery = requestedClaims.firstOrNull {
                    it.id == claim
                } ?: continue

                val namespace = (claimQuery.path[0] as PointerPart.String).v1
                val claimName = (claimQuery.path[1] as PointerPart.String).v1

                val theNamespace = this.mdoc.originalDecoded["nameSpaces"][namespace]
                if (theNamespace == Value.Null) {
                    continue@setLoop
                }
                val element = theNamespace.asArray()!!
                    .map {
                        decodeCbor(it.asTag()!!.value[0].asBytes()!!)
                    }
                    .firstOrNull() { it["elementIdentifier"].asString()!! == claimName }
                    ?: Value.Null
                if (element.isSame(Value.Null)) {
                    continue@setLoop
                }
                // Ensure the value matches the predicates
                val allowedValues = claimQuery.values
                if (allowedValues != null) {
                    if (!allowedValues.any { it.isSame(element) }) {
                        return Result.failure(InvalidClaimsQuery(claimQuery))
                    }
                }
                val namespaceElements = disclosurePtrs.getOrPut(namespace) { mutableListOf() }
                namespaceElements.add((24 to encodeCbor(element)).toCbor())
            }
            // we passed all options, so lets add them to the token and return
            for (ptr in disclosurePtrs) {
                var entry = namespaces.getOrPut(ptr.key) { mutableListOf() }
                entry.addAll(ptr.value)
            }
            issuerSigned = mapOf(
                "issuerAuth" to originalIssuerAuth,
                "nameSpaces" to namespaces
            ).toCbor()

            val token = this.buildToken(
                signer,
                issuerSigned,
                sessionTranscript,
            )

            return Result.success(
                base64UrlEncode(encodeCbor(token))
            )
        }

        issuerSigned = mapOf(
            "issuerAuth" to originalIssuerAuth,
            "nameSpaces" to listOf<String>()
        ).toCbor()
        val token = this.buildToken(
            signer,
            issuerSigned,
            sessionTranscript,
        )

        return Result.success(
            base64UrlEncode(encodeCbor(token))
        )
    }
    issuerSigned = mapOf(
        "issuerAuth" to originalIssuerAuth,
        "nameSpaces" to namespaces
    ).toCbor()
    val token = this.buildToken(
        signer,
        issuerSigned,
        sessionTranscript,
    )

    return Result.success(
        base64UrlEncode(encodeCbor(token))
    )
}
