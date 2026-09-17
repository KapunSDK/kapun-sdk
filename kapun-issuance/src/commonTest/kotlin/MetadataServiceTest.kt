import org.kapunsdk.issuance.metadata.MetadataService
import org.kapunsdk.issuance.metadata.data.CredentialConfiguration
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadataClaims
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class MetadataServiceTest {
    @Test
    fun testOidcCredentialIssuerEndpoint() {
        var url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/issuer")
        assertEquals("https://example.com/issuer/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/issuer/")
        assertEquals("https://example.com/issuer/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/issuer/path")
        assertEquals("https://example.com/issuer/path/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())
    }

    @Test
    fun testIetfCredentialIssuerEndpoint() {
        var url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/issuer")
        assertEquals("https://example.com/.well-known/openid-credential-issuer/issuer", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/issuer/")
        assertEquals("https://example.com/.well-known/openid-credential-issuer/issuer/", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/issuer/path")
        assertEquals("https://example.com/.well-known/openid-credential-issuer/issuer/path", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())
    }

    @Test
    fun testBbsCredentialConfiguration() {
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

        val configuration = assertIs<CredentialConfiguration.Bbs>(
            metadata.credentialConfigurationsSupported.getValue("bbs")
        )
        assertEquals("urn:example:bbs", configuration.vct)
        assertEquals("BBS credential", configuration.getDisplayMetadata()?.single()?.name)
    }
}
