package org.kapunsdk.trust.framework.swiss

import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNotNull

class BcsDidHttpProbeTest {
    @Test
    fun fetchesBcsDidDocumentsOverHttp() {
        runBlocking {
        val client = HttpClient()
        try {
            val service = SwissTrustService(client)
            assertNotNull(
                service.getDidDocument(
                    "did:webvh:QmdPxnNc9MzGYZ6qcHuvi8YpDVYWW7mmefnCTPcKapNEL5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:5f8a3c95-1772-4ebf-ada0-c88bafb258e1"
                )
            )
            assertNotNull(
                service.getDidDocument(
                    "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527"
                )
            )
        } finally {
            client.close()
        }
        }
    }
}
