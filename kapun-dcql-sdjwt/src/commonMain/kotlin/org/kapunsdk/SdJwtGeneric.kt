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

import org.kapunsdk.credentials.*
import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.get
import uniffi.kapun_credential_core_rust.*
import uniffi.kapun_credential_core_rust.SignatureCreator
import uniffi.kapun_dcql_sdjwt_rust.*
import uniffi.kapun_dcql_rust.CombinedSdJwtMetaMismatch
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.CredentialLike
import uniffi.kapun_dcql_rust.CredentialParser
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_dcql_rust.Meta
import uniffi.kapun_dcql_rust.MetaMismatch
import uniffi.kapun_dcql_rust.registerParser
import uniffi.kapun_util_rust.*
import kotlin.text.iterator

object SdJwtParser: CredentialParser {

    init {
        register()
    }

    fun register() = registerParser(this)

    override fun id(): String {
        return "sdjwt-parser"
    }

    override fun fromStr(credential: String): Credential? {
        val sdjwt = runCatching { decodeSdjwt(credential) }.getOrNull() ?: return null
        if (sdjwt.claims["@context"] != Value.Null) return null
        return Credential.SdJwtCredential(SdJwtCredential(sdjwt))
    }
}

class SdJwtCredential(val sdjwt: SdJwtRust): CredentialLike {
    override fun getBody(): Value {
        return sdjwt.claims
    }

    override fun serialize(): String {
        return sdjwt.originalSdjwt
    }

    override fun formatSpecifiers(): List<String> {
       return listOf("dc+sd-jwt", "vc+sd-jwt")
    }

    override fun matchesMeta(meta: Meta?): MetaMismatch? {
        val vct = this.sdjwt.claims["vct"].asString() ?: return MetaMismatch.SdJwtMetaMismatch(CombinedSdJwtMetaMismatch.WRONG_VCT_VALUE)
        return when(meta) {
            is Meta.SdjwtVc -> {
                if(meta.vctValues.any { vct == it }){
                    null
                } else {
                    MetaMismatch.SdJwtMetaMismatch(CombinedSdJwtMetaMismatch.WRONG_VCT_VALUE)
                }
            }
            else if meta == null -> null
            else -> MetaMismatch.SdJwtMetaMismatch(CombinedSdJwtMetaMismatch.INVALID_META)
        }
    }

    override fun get(selector: Selector): List<Value>? {
        return runCatching { sdjwt.claims[selector] }.getOrNull()
    }
}
fun SdJwtBuilder.getVpToken(
    claims: Value,
    query: CredentialQuery,
    audience: String,
    transactionData: List<String>?,
    specVersion: SpecVersion?,
    nonce: String,
    signer: SignatureCreator?,
    overrideDisclosures: List<List<PointerPart>>? = null
) : Result<String> {
    this.withAudience(audience)
    this.withNonce(nonce)

    if(transactionData != null && specVersion != null) {
        this.withTransactionData(transactionData, specVersion);
    }

    // useful for tests
    overrideDisclosures?.let {
        it.forEach { ptr -> this.addDisclosure(ptr) }
        return Result.success(this.build(signer.asNativeSdJwtSignatureCreator()))
    }

    // If claims is absent, no selectively disclosable claims are requested. Treat an empty legacy
    // value the same way so that invalid input fails closed instead of disclosing data.
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
    if(query.claims.isNullOrEmpty()){
        this.removeAll()
        return Result.success(this.build(signer.asNativeSdJwtSignatureCreator()))
    }

    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims
    val requestedClaims = query.claims.orEmpty()
    val requestedClaimSets = query.claimSets
    if(requestedClaimSets == null){
        for(claim in requestedClaims){
            val path = if (this.isW3c() && claim.path.firstOrNull() != PointerPart.String("credentialSubject")) {
                listOf(PointerPart.String("credentialSubject")) + claim.path
            } else {
                claim.path
            }
            val ptrs = resolvePointer(claims, path)
            for (ptr in ptrs) {
                val r = claims[ptr.asSelector()]
                if(r.size > 1 || r.isEmpty()) {
                    return Result.failure(SdJwtErrors.InvalidDisclosurePath(claim.path))
                }
                this.addDisclosure(ptr)
            }
        }
    } else  {
        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets.
        // The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet MUST return the first option that it can satisfy.
        // If the Wallet cannot satisfy any of the options, it MUST NOT return any claims
        setLoop@ for (option in requestedClaimSets){
            var disclosurePtrs = mutableListOf<List<PointerPart>>()
            for(claim in option) {
                val claimQuery = requestedClaims.firstOrNull { it.id == claim } ?: continue
                val ptrs = resolvePointer(claims, claimQuery.path)
                if(ptrs.isEmpty()) {
                    // we don't have claims matching the query, so skip these options
                    continue@setLoop
                }
                for(ptr in ptrs) {
                    val res = ptr.asSelector().select(claims)
                    if (res.isEmpty()) {
                        continue@setLoop
                    }
                }
                disclosurePtrs.addAll(ptrs)
            }
            // we passed all options, so lets add them to the token and return
            for(ptr in disclosurePtrs){
                try {
                    this.addDisclosure(ptr)
                }catch (e: Exception) {
                    println(e)
                }
            }
            return Result.success(this.build(signer.asNativeSdJwtSignatureCreator()))
        }
        this.removeAll()
        return Result.success(this.build(signer.asNativeSdJwtSignatureCreator()))
    }
    return Result.success(this.build(signer.asNativeSdJwtSignatureCreator()))
}

private fun resolvePointer(claims: Value, ptr: List<PointerPart>) : List<List<PointerPart>> {
    val p = ClaimsPointer(ptr)
    return p.resolvePtr(claims)
}
