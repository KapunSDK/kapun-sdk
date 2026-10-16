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
import org.kapunsdk.visualization.oca.model.OcaBundleJson
import org.kapunsdk.visualization.oca.model.json
import org.kapunsdk.visualization.oca.model.overlay.presentation.ClusterOrderingOverlay
import org.kapunsdk.visualization.oca.model.overlay.presentation.UbiqueStyleJsonOverlay
import org.kapunsdk.visualization.oca.model.overlay.semantic.LabelOverlay
import org.kapunsdk.visualization.oca.processing.OcaProcessor
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

    @Test
    fun testClaimLabelsAreLocalizedFromMetadata() {
        val metadata = Json { ignoreUnknownKeys = true }.decodeFromString<CredentialIssuerMetadataClaims>(
            """
            {
              "credential_issuer": "https://issuer.example",
              "credential_endpoint": "https://issuer.example/credential",
              "credential_configurations_supported": {
                "sdjwt": {
                  "format": "dc+sd-jwt",
                  "vct": "urn:example:sdjwt",
                  "credential_metadata": {
                    "claims": [
                      { "path": ["given_name"], "display": [{ "name": "Given name", "locale": "en" }, { "name": "Vorname", "locale": "de" }] },
                      { "path": ["family_name"], "display": [{ "name": "Nachname", "locale": "de" }] },
                      { "path": ["address", "street_address"], "display": [{ "name": "Street", "locale": "en" }, { "name": "Strasse", "locale": "de-CH" }] },
                      { "path": ["nationalities", null], "display": [{ "name": "Nationalities", "locale": "en" }, { "name": "Nationalitäten", "locale": "de" }] }
                    ]
                  }
                }
              }
            }
            """.trimIndent()
        )
        val payload = """{"given_name":"Alice","family_name":"Muster","nickname":"Ali","address":{"street_address":"Main St"},"nationalities":["CH"]}"""

        val bundle = assertNotNull(
            OcaBundleFactory.createOcaFromDisplayMetadata(
                locale = "en",
                stringResourceProvider = object : StringResourceProvider {
                    override fun getString(stringName: String) = "builtin:$stringName"
                },
                backgroundImage = null,
                metadata = metadata,
                vct = "urn:example:sdjwt",
                jsonContent = payload,
            )
        )

        val labelOverlays = bundle.overlays.filterIsInstance<LabelOverlay>().associateBy { it.language }
        // Device locale first, followed by the issuer locales
        assertEquals(listOf("en", "de", "de-CH"), labelOverlays.keys.toList())

        val en = labelOverlays.getValue("en")
        assertEquals("Given name", en.getLabel("/given_name")) // issuer before built-in
        assertEquals("builtin:id_last_name", en.getLabel("/family_name")) // built-in before other issuer languages
        assertEquals("Street", en.getLabel("/address/street_address"))
        assertEquals("Nationalities", en.getLabel("/nationalities"))
        assertEquals("/nickname", en.getLabel("/nickname"))

        val de = labelOverlays.getValue("de")
        assertEquals("Vorname", de.getLabel("/given_name"))
        assertEquals("Nachname", de.getLabel("/family_name"))
        assertEquals("Strasse", de.getLabel("/address/street_address")) // language match of de-CH
        assertEquals("Nationalitäten", de.getLabel("/nationalities"))
        assertEquals("/nickname", de.getLabel("/nickname"))

        // The stored bundle picks the label matching the current user language
        val storedBundle = json.decodeFromString<OcaBundleJson>(json.encodeToString(bundle))
        fun label(userLanguage: String, attributeName: String) =
            OcaProcessor(userLanguage, payload, storedBundle).processAttribute(attributeName)?.label

        assertEquals("Given name", label("en-US", "/given_name"))
        assertEquals("Vorname", label("de-CH", "/given_name"))
        assertEquals("Strasse", label("de-CH", "/address/street_address"))
        assertEquals("Given name", label("fr", "/given_name")) // falls back to the device locale
    }

    @Test
    fun testClusterOrderingUsesFullAttributePathAndLocalizedClusterLabels() {
        val metadata = Json { ignoreUnknownKeys = true }.decodeFromString<CredentialIssuerMetadataClaims>(
            """
            {
              "credential_issuer": "https://issuer.example",
              "credential_endpoint": "https://issuer.example/credential",
              "credential_configurations_supported": {
                "sdjwt": { "format": "dc+sd-jwt", "vct": "urn:example:sdjwt" }
              },
              "credential_metadata": {
                "claims": [
                  { "path": ["address"], "display": [{ "name": "Address", "locale": "en" }, { "name": "Adresse", "locale": "de" }] },
                  { "path": ["address", "street_address"] },
                  { "path": ["address", "locality"] },
                  { "path": ["nickname"] }
                ]
              }
            }
            """.trimIndent()
        )

        val bundle = assertNotNull(
            OcaBundleFactory.createOcaFromDisplayMetadata(
                locale = "en",
                stringResourceProvider = object : StringResourceProvider {
                    override fun getString(stringName: String) = stringName
                },
                backgroundImage = null,
                metadata = metadata,
                vct = "urn:example:sdjwt",
                jsonContent = """{"nickname":"Ali","address":{"street_address":"Main St","locality":"Bern"}}""",
            )
        )

        val clusterOverlays = bundle.overlays.filterIsInstance<ClusterOrderingOverlay>().associateBy { it.language }
        assertEquals(listOf("en", "de"), clusterOverlays.keys.toList())

        val en = clusterOverlays.getValue("en")
        assertEquals(
            mapOf("/address/street_address" to 1, "/address/locality" to 2),
            en.attributeClusterOrder["address"],
        )
        assertEquals(mapOf("/nickname" to 1), en.attributeClusterOrder["additional"])
        assertEquals("Address", en.clusterLabels["address"])
        assertEquals("Adresse", clusterOverlays.getValue("de").clusterLabels["address"])
    }

    @Test
    fun testRegionalIssuerLocalesMatchAppLanguage() {
        val metadata = Json { ignoreUnknownKeys = true }.decodeFromString<CredentialIssuerMetadataClaims>(
            """
            {
              "credential_issuer": "https://issuer.example",
              "credential_endpoint": "https://issuer.example/credential",
              "credential_configurations_supported": {
                "sdjwt": {
                  "format": "dc+sd-jwt",
                  "vct": "urn:example:sdjwt",
                  "credential_metadata": {
                    "claims": [
                      { "path": ["nickname"], "display": [{ "name": "Nickname", "locale": "en-US" }, { "name": "Spitzname", "locale": "de-CH" }] }
                    ]
                  }
                }
              }
            }
            """.trimIndent()
        )
        val payload = """{"nickname":"Ali"}"""

        // Issued while the app language was "de", the issuer only provides regional locales
        val bundle = assertNotNull(
            OcaBundleFactory.createOcaFromDisplayMetadata(
                locale = "de",
                stringResourceProvider = object : StringResourceProvider {
                    override fun getString(stringName: String) = stringName
                },
                backgroundImage = null,
                metadata = metadata,
                vct = "urn:example:sdjwt",
                jsonContent = payload,
            )
        )
        fun label(userLanguage: String) =
            OcaProcessor(userLanguage, payload, bundle).processAttribute("/nickname")?.label

        assertEquals("Spitzname", label("de"))
        assertEquals("Nickname", label("en")) // matches the en-US overlay by language
        assertEquals("Spitzname", label("fi")) // no issuer label, falls back to the issuance language
    }
}
