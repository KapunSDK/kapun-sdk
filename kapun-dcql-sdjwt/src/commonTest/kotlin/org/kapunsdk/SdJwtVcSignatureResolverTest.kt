package org.kapunsdk

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.kapunsdk.credentials.sdjwt.SdJwtVcSignatureResolver

class SdJwtVcSignatureResolverTest {
    @Test
    fun issuerMetadataDiscoveryIgnoresNonHttpIdentifiers() {
        assertNull(SdJwtVcSignatureResolver.jwtVcIssuerMetadataUrl("did:tdw:example.com:issuer"))
        assertNull(SdJwtVcSignatureResolver.jwtVcIssuerMetadataUrl("urn:issuer"))
        assertNull(SdJwtVcSignatureResolver.jwtVcIssuerMetadataUrl("issuer.example.com"))
    }

    @Test
    fun issuerMetadataDiscoveryBuildsHttpUrl() {
        val url = assertNotNull(
            SdJwtVcSignatureResolver.jwtVcIssuerMetadataUrl("https://issuer.example/tenant")
        )

        assertTrue(url.toString().startsWith("https://issuer.example"))
    }
}
