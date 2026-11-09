/* Copyright 2024 Ubique Innovation AG

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
package org.kapunsdk.visualization.oca.profile

import kotlinx.coroutines.runBlocking
import kotlinx.datetime.LocalDate
import org.kapunsdk.visualization.oca.model.content.AttributeType
import org.kapunsdk.visualization.oca.model.overlay.presentation.OrderOverlay
import org.kapunsdk.visualization.oca.model.overlay.transformation.DataSourceOverlay
import org.kapunsdk.visualization.oca.processing.AttributeValue
import org.kapunsdk.visualization.test.readResourceAsString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Uses a training record bundle in the Swiss VC profile format: a root capture base referencing a `person`
 * capture base and a list of `courses` capture bases, located in the credential by data source overlays.
 */
class OcaProfileProcessorTest {
    @Test
    fun `parses all capture bases references and the profile overlays`(): Unit =
        runBlocking {
            val bundle = bundle()

            assertEquals("swiss-profile-vc:1.0.0", bundle.profileVersion)
            assertEquals(3, bundle.captureBases.size)
            assertEquals(ROOT, bundle.rootDigest)
            assertEquals(CaptureBaseReference(PERSON, isArray = false), bundle.reference(ROOT, "person"))
            assertEquals(CaptureBaseReference(COURSE, isArray = true), bundle.reference(ROOT, "courses"))
            assertEquals(null, bundle.reference(ROOT, "note"))
            // References keep their existing attribute types.
            assertEquals(AttributeType.Unknown, bundle.captureBases.getValue(ROOT).attributes["person"])
            assertEquals(3, bundle.overlays.filterIsInstance<DataSourceOverlay>().size)
            assertEquals(3, bundle.overlays.filterIsInstance<OrderOverlay>().size)
            // The overlay of an unknown type is skipped.
            assertEquals(bundle.overlaysJson.size - 1, bundle.overlays.size)
        }

    @Test
    fun `verifies the capture base digests`(): Unit =
        runBlocking {
            assertTrue(bundle().verifyIntegrity())

            val tampered = readResourceAsString(BUNDLE).replace("\"memberId\": \"Text\"", "\"memberId\": \"Numeric\"")
            assertFalse(OcaProfileBundleJson.fromJson(tampered).verifyIntegrity())
        }

    @Test
    fun `processes the credential in order with labels and typed values`(): Unit =
        runBlocking {
            val processed = assertNotNull(process("de"))

            assertEquals("Ausbildungsnachweis", processed.name)
            assertEquals("#2f4f4f", processed.primaryBackgroundColor)
            assertEquals(listOf("person", "courses", "note"), processed.root.children.map { it.attributeName })

            val person = assertIs<ProcessedOcaNode.Group>(processed.root.children[0])
            assertEquals("Person", person.label)
            assertEquals(
                listOf("photo", "familyName", "givenName", "birthDate", "memberId"),
                person.children.map {
                    it.attributeName
                },
            )
            assertEquals("Name", person.attribute("familyName")?.label)
            assertEquals(AttributeValue.Text("Muster"), person.attribute("familyName")?.attributeValue)
            assertEquals(AttributeValue.Date(LocalDate(1990, 4, 12)), person.attribute("birthDate")?.attributeValue)
            assertIs<AttributeValue.Image>(person.attribute("photo")?.attributeValue)
            // Nested data source path.
            assertEquals(AttributeValue.Text("M-001"), person.attribute("memberId")?.attributeValue)
        }

    @Test
    fun `array of references gives one group per element`(): Unit =
        runBlocking {
            val processed = assertNotNull(process("de"))

            val courses = assertIs<ProcessedOcaNode.GroupList>(processed.root.children[1])
            assertEquals("Kurs First aid, Fire safety", courses.label)
            assertEquals(listOf("Kurs First aid", "Kurs Fire safety"), courses.items.map { it.label })
            val fireSafety = courses.items[1]
            assertEquals(listOf("name", "completedOn", "validUntil"), fireSafety.children.map { it.attributeName })
            assertEquals(
                AttributeValue.Date(LocalDate(2022, 3, 1)),
                fireSafety.attribute("completedOn")?.attributeValue,
            )
            assertEquals(AttributeValue.Text("2025-01-23"), fireSafety.attribute("validUntil")?.attributeValue)
            assertEquals("Gültig bis", fireSafety.attribute("validUntil")?.label)
        }

    @Test
    fun `labels follow the user language`(): Unit =
        runBlocking {
            val processed = assertNotNull(process("fr-CH"))

            val person = assertIs<ProcessedOcaNode.Group>(processed.root.children[0])
            assertEquals("Nom", person.attribute("familyName")?.label)
            assertEquals("Attestation de formation", processed.name)
        }

    @Test
    fun `attributes missing in the credential have no value`(): Unit =
        runBlocking {
            val payload = readResourceAsString(PAYLOAD).replace("\"familyName\": \"Muster\",", "")
            val processed = assertNotNull(OcaProfileProcessor("de", payload, bundle()).process())

            val person = assertIs<ProcessedOcaNode.Group>(processed.root.children[0])
            assertEquals(null, person.attribute("familyName")?.attributeValue)
        }

    @Test
    fun `no array in the credential gives an empty list`(): Unit =
        runBlocking {
            val payload = readResourceAsString(PAYLOAD).substringBefore(",\n  \"courses\"") + "\n}"
            val processed = assertNotNull(OcaProfileProcessor("de", payload, bundle()).process())

            assertEquals(emptyList(), assertIs<ProcessedOcaNode.GroupList>(processed.root.children[1]).items)
        }

    private suspend fun bundle() = OcaProfileBundleJson.fromJson(readResourceAsString(BUNDLE))

    private suspend fun process(language: String) =
        OcaProfileProcessor(language, readResourceAsString(PAYLOAD), bundle()).process()

    private companion object {
        const val BUNDLE = "files/oca/swiss_profile/training_record_oca.json"
        const val PAYLOAD = "files/oca/swiss_profile/training_record_payload.json"
        const val ROOT = "IGYIaBR88bya5R1nX2lLFWI4GRDP1CENEGpstlZVTCnE"
        const val PERSON = "IBvsL_HyHdrLV0U3_sbJVm3lDtE5pNyI6ziGwwUHisHd"
        const val COURSE = "IO0jbaq2s-oak9u1LRl9rEsow2ik8yFbzdL090iQd7mL"
    }
}
