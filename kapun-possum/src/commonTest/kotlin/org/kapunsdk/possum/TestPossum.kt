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

package org.kapunsdk.possum

import uniffi.kapun_possum_rust.PossumException
import uniffi.kapun_possum_rust.PossumExpression
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TestPossum {
    @Test
    fun testPossum() {
        val expression =
            """
                /* TEST COMMENT */
            if (
                /* OTHER */
                payload.v.0.tg === external.acceptance-criterias.diseases.hytu ?? "test"
                &&
                payload.v.0.dn >= payload.v.0.sd
                && payload.v.0.sd >= 2
                && payload.v.0.dn == 2
            )
            {
                 /* OTHER */
                true
            } else
            {
                 /* OTHER */
                false
            }
            """.trimIndent()
        val data =
            """
                    {
                    "external": {
                        "acceptance-criterias" : {
                            "diseases" : {
                                "hytu" : "8539006"
                            }
                        }
                    },
                    "payload" : {
                    "nam": {
                        "fn": "Müller",
                        "fnt": "MUELLER",
                        "gn": "Céline",
                        "gnt": "CELINE"
                    },
                    "dob": "1943-02-01",
                    "ver": "1.0.0",
                    "v": [
                        {
                            "tg": "8539006",
                            "vp": "1119007",
                            "mp": "EU/10/1507",
                            "ma": "ORG-100084",
                            "dn": 2,
                            "sd": 2,
                            "dt": "2021-04-30",
                            "co": "CH",
                            "is": "Musteramt",
                            "ci": "11111"
                        }
                    ]
                }
            }
            """.trimIndent()

        val pe = PossumExpression.fromStr(expression)
        val result = pe.evaluate(data)
        assertTrue { result.isTruthy() }
    }

    private val data =
        """
        {
            "external": {"validationClock": "2026-10-27T10:15:00Z"},
            "claims": {"dateOfExpiration": "2031-10-27", "categories": [{"code": "B"}, {"code": "C"}]}
        }
        """.trimIndent()

    @Test
    fun parseReportsInvalidSource() {
        assertFailsWith<PossumException.Parse> { PossumExpression.parse("claims.x is after") }
    }

    @Test
    fun evaluateBoolComparesDates() {
        assertTrue(PossumExpression.parse("(claims.dateOfExpiration as DateTime) is after now()").evaluateBool(data))
        assertFalse(PossumExpression.parse("claims.missing == true").evaluateBool(data))
    }

    @Test
    fun evaluateJsonReturnsAnyValue() {
        assertEquals("\"C\"", PossumExpression.parse("claims.categories.1.code").evaluateJson(data))
        assertEquals("""[{"code":"B"},{"code":"C"}]""", PossumExpression.parse("claims.categories").evaluateJson(data))
        assertEquals("null", PossumExpression.parse("claims.missing").evaluateJson(data))
    }

    @Test
    fun evaluateBoolRejectsNonBooleans() {
        assertFailsWith<PossumException.Evaluation> {
            PossumExpression
                .parse(
                    "claims.dateOfExpiration",
                ).evaluateBool(data)
        }
    }
}
