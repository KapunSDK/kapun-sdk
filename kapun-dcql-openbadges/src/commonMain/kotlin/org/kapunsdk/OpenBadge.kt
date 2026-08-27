/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package org.kapunsdk

import org.kapunsdk.credentials.get
import uniffi.kapun_credential_core_rust.Selector
import uniffi.kapun_dcql_w3c_rust.W3cVerifiableCredential
import uniffi.kapun_dcql_w3c_rust.parseCanonicalizedW3cJsonLd
import uniffi.kapun_dcql_w3c_rust.w3cCredentialAsJson
import uniffi.kapun_dcql_rust.CombinedLdpMetaMismatch
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.CredentialLike
import uniffi.kapun_dcql_rust.CredentialParser
import uniffi.kapun_dcql_rust.Meta
import uniffi.kapun_dcql_rust.MetaMismatch
import uniffi.kapun_dcql_rust.registerParser
import uniffi.kapun_util_rust.Value

object OpenBadgeParser : CredentialParser {
    init {
        register()
    }

    fun register() = registerParser(this)

    override fun id(): String = "openbadges-3-parser"

    override fun fromStr(credential: String): Credential? {
        val parsed = runCatching { parseCanonicalizedW3cJsonLd(credential) }.getOrNull()
            ?: return null
        if (!parsed.types.contains("OpenBadgeCredential")) return null
        return Credential.OpenBadge303Credential(OpenBadgeCredential(parsed, credential))
    }
}

class OpenBadgeCredential(
    private val credential: W3cVerifiableCredential,
    private val serialized: String,
) : CredentialLike {
    private val credentialBody by lazy { w3cCredentialAsJson(credential) }

    override fun getBody(): Value = credentialBody

    override fun serialize(): String = serialized

    override fun formatSpecifiers(): List<String> = listOf("ldp_vc")

    override fun matchesMeta(meta: Meta?): MetaMismatch? = when (meta) {
        is Meta.LdpVc -> if (meta.typeValues.any { expected -> expected.all(credential.types::contains) }) {
            null
        } else {
            MetaMismatch.LdpMetaMismatch(CombinedLdpMetaMismatch.WRONG_CREDENTIAL_TYPES)
        }
        null -> null
        else -> MetaMismatch.LdpMetaMismatch(CombinedLdpMetaMismatch.INVALID_META)
    }

    override fun get(selector: Selector): List<Value>? = credentialBody[selector]
}
