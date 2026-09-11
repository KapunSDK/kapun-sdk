/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package org.kapunsdk

import org.kapunsdk.credentials.get
import org.kapunsdk.util.extensions.get
import uniffi.kapun_credential_core_rust.Selector
import uniffi.kapun_dcql_w3c_rust.W3cSdJwt
import uniffi.kapun_dcql_w3c_rust.parseW3cSdJwt
import uniffi.kapun_dcql_rust.Credential
import uniffi.kapun_dcql_rust.CredentialLike
import uniffi.kapun_dcql_rust.CredentialParser
import uniffi.kapun_dcql_rust.Meta
import uniffi.kapun_dcql_rust.MetaMismatch
import uniffi.kapun_dcql_rust.registerParser
import uniffi.kapun_util_rust.Value

object W3CParser : CredentialParser {
    init {
        register()
    }

    fun register() = registerParser(this)

    override fun id(): String = "w3c-sdjwt-parser"

    override fun fromStr(credential: String): Credential? {
        val parsed = runCatching { parseW3cSdJwt(credential) }.getOrNull() ?: return null
        if (parsed.json["@context"] == Value.Null) return null
        return Credential.W3cCredential(W3CCredential(parsed))
    }
}

class W3CCredential(private val w3c: W3cSdJwt) : CredentialLike {
    override fun getBody(): Value = w3c.json

    override fun serialize(): String = w3c.originalSdjwt

    override fun formatSpecifiers(): List<String> = listOf("vc+sd-jwt")

    override fun matchesMeta(meta: Meta?): MetaMismatch? = null

    override fun get(selector: Selector): List<Value>? = runCatching { w3c.json[selector] }.getOrNull()
}
