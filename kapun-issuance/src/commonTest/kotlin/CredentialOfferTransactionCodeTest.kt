import kotlinx.serialization.json.Json
import org.kapunsdk.issuance.credential.offer.CredentialOfferParameters
import org.kapunsdk.issuance.credential.offer.InputMode
import org.kapunsdk.issuance.credential.offer.PreAuthorizedCode
import kotlin.test.*

class CredentialOfferTransactionCodeTest {
    // OpenID4VCI 1.0 Final §4.1.1 published Credential Offer example.
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#section-4.1.1
    @Test
    fun parsesFinalSpecificationCredentialOffer() {
        val offer = Json.decodeFromString<CredentialOfferParameters>("""
            {
              "credential_issuer": "https://credential-issuer.example.com",
              "credential_configuration_ids": ["UniversityDegreeCredential", "org.iso.18013.5.1.mDL"],
              "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                  "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
                  "tx_code": {
                    "length": 4,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code that was sent via e-mail"
                  }
                }
              }
            }
        """)
        val grant = assertNotNull(offer.grants?.preAuthorizedCode)
        assertEquals("oaKazRN8I0IbtZ0C7JuMn5", grant.preAuthorizedCode)
        val code = assertNotNull(grant.txCode)
        assertEquals(4, code.length)
        assertEquals(InputMode.NUMERIC, code.inputMode)
    }

    // §4.1.1 and §6.1: even an empty tx_code object requires a code in the token request.
    @Test
    fun distinguishesEmptyTransactionCodeObjectFromAbsentCode() {
        val required = Json.decodeFromString<PreAuthorizedCode>("""{"pre-authorized_code":"code","tx_code":{}}""")
        val optional = Json.decodeFromString<PreAuthorizedCode>("""{"pre-authorized_code":"code"}""")
        val code = assertNotNull(required.txCode)
        assertNull(code.inputMode) // Consumers must interpret omission as numeric (final §4.1.1).
        assertNull(code.length)
        assertNull(optional.txCode)
    }

    @Test
    fun textTransactionCodesRemainSupported() {
        val grant = Json.decodeFromString<PreAuthorizedCode>("""{"pre-authorized_code":"code","tx_code":{"input_mode":"text"}}""")
        assertEquals(InputMode.TEXT, assertNotNull(grant.txCode).inputMode)
    }
}
