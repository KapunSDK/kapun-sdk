/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

package org.kapunsdk.wallet.credentials.mapping.defaults

import kotlinx.serialization.json.Json
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadataClaims
import org.kapunsdk.visualization.oca.model.overlay.presentation.UbiqueStyleJsonOverlay
import org.kapunsdk.wallet.resources.StringResourceProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class OcaBundleFactoryTest {
    @Test
    fun testBbsMetadataDisplayIsUsedForOca() {
        val metadata = Json { ignoreUnknownKeys = true }.decodeFromString<CredentialIssuerMetadataClaims>(
            """
            {
              "credential_issuer": "https://issuer.example",
              "credential_endpoint": "https://issuer.example/credential",
              "credential_configurations_supported": {
                "bbs": {
                  "format": "zkp_vc",
                  "vct": "urn:example:bbs",
                  "credential_metadata": {
                    "display": [
                      { "name": "BBS credential", "locale": "en-US" }
                    ]
                  }
                }
              }
            }
            """.trimIndent()
        )

        val bundle = OcaBundleFactory.createOcaFromDisplayMetadata(
            locale = "en-US",
            stringResourceProvider = object : StringResourceProvider {
                override fun getString(stringName: String) = stringName
            },
            backgroundImage = null,
            metadata = metadata,
            vct = "urn:example:bbs",
            jsonContent = "{\"name\":\"Alice\"}",
        )

        val style = assertNotNull(bundle)
            .overlays
            .filterIsInstance<UbiqueStyleJsonOverlay>()
            .single()
        assertEquals("BBS credential", style.title)
    }
}
