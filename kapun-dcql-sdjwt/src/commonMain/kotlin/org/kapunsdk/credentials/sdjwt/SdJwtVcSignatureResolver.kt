/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.kapunsdk.credentials.sdjwt

import org.kapunsdk.util.extensions.asString
import org.kapunsdk.util.extensions.get
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.path
import io.ktor.http.takeFrom
import kotlinx.serialization.json.Json
import uniffi.kapun_crypto_rust.parseEncodedJwtPayload
import uniffi.kapun_util_rust.Value

object SdJwtVcSignatureResolver {

    /**
     * JWT VC issuer metadata is an HTTP(S) discovery mechanism.  An issuer may
     * also be identified by a DID, but a DID is not an issuer-metadata URL and
     * must be handled by the corresponding DID verification method instead.
     */
    internal fun jwtVcIssuerMetadataUrl(issuer: String): Url? {
        val scheme = issuer.substringBefore(':', missingDelimiterValue = "")
        if (!scheme.equals("http", ignoreCase = true) &&
            !scheme.equals("https", ignoreCase = true)
        ) {
            return null
        }

        return runCatching {
            URLBuilder()
                .takeFrom(issuer)
                .apply {
                    val path = arrayOf(".well-known", "jwt-vc-issuer") + encodedPathSegments
                    path(*path)
                }
                .build()
        }.getOrNull()
    }

    private fun retrievePkUsingJwtVcIssuerMetadata(jwt: String): Value? {
        // Issuer metadata is optional.  Failure to parse or resolve it must
        // not prevent callers from receiving/processing the credential; it is
        // only relevant when signature verification is explicitly requested.
        val issuer = runCatching {
            parseEncodedJwtPayload(jwt)
                ?.let { Json.decodeFromString<Value>(it)["iss"].asString() }
        }.getOrNull() ?: return null

        // A DID (or any other non-HTTP identifier) is not a URL for this
        // discovery mechanism.  In particular, do not turn a DID into a
        // network request just because it is present in `iss`.
        jwtVcIssuerMetadataUrl(issuer) ?: return null

        // TODO: fetch `url`, select the key identified by the JWT header's
        // `kid`, and verify the JWT.  Keep this optional lookup best-effort
        // until the metadata verification implementation is available.
        return null
    }

    private fun retrievePkUsingX509Cert(): Value? {
        // TODO
        return null
    }

    private fun retrievePkUsingDidWeb(): Value? {
        // TODO
        return null
    }

    fun isSignatureValid(jwt: String): Boolean {
        val pk = retrievePkUsingJwtVcIssuerMetadata(jwt)
            ?: retrievePkUsingX509Cert()
            ?: retrievePkUsingDidWeb()
            ?: return false

        // TODO: "Verify the jwt using the public key"

        return false
    }
}
