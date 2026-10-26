/* Copyright 2026 Ubique Innovation AG

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

package org.kapunsdk.trust

import kotlinx.coroutines.test.runTest
import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.framework.DocumentProvider
import org.kapunsdk.trust.framework.germany.EuTrustFramework
import org.kapunsdk.trust.framework.oid4vp.Oid4VpTrustFramework
import org.kapunsdk.trust.framework.oid4vp.StaticDidWebTrustAnchorProvider
import org.kapunsdk.trust.framework.swiss.SwissTrustFramework
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The frameworks that take their dependencies from the trust module's Koin context must work on the
 * JVM once [KapunTrust.initialize] has run, as they do on Android and iOS.
 */
class KapunTrustJvmTest {
    private val noDocuments =
        object : DocumentProvider {
            override suspend fun getAllCredentials(): List<CredentialModel> = emptyList()

            override suspend fun getCredentialsByDocType(
                docType: String,
                includeUsedCredentials: Boolean,
            ): List<CredentialModel> = emptyList()
        }

    @BeforeTest
    fun initialize() {
        KapunTrust().initialize()
    }

    @Test
    fun `swiss framework resolves its repository from the Koin context`() =
        runTest {
            val framework = SwissTrustFramework(noDocuments)

            val validation =
                framework.validatePresentationRequest(
                    PresentationRequest(clientId = "redirect_uri:https://verifier.example"),
                )

            assertTrue(validation.isValid)
        }

    @Test
    fun `basic framework names a verifier without client name or signed request by its client id`() =
        runTest {
            val framework =
                Oid4VpTrustFramework(
                    documentProvider = noDocuments,
                    didWebTrustAnchorProvider = StaticDidWebTrustAnchorProvider(),
                    trustedDomains = emptyList(),
                )
            val clientId = "redirect_uri:https://verifier.example"

            val agent = framework.getVerifierInformation("", PresentationRequest(clientId = clientId), null)

            assertEquals(clientId, agent.displayName)
            assertFalse(agent.isTrusted)
        }

    @Test
    fun `eu framework leaves a request passed by value to the other frameworks`() =
        runTest {
            val framework = EuTrustFramework(noDocuments, trustedDomains = emptyList())

            val agent =
                framework.getVerifierInformation(
                    "",
                    PresentationRequest(clientId = "redirect_uri:https://verifier.example"),
                    null,
                )

            assertNull(agent)
        }
}
