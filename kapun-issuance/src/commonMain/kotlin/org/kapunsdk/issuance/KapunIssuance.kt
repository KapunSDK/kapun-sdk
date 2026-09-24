package org.kapunsdk.issuance

import org.kapunsdk.util.network.KapunNetworkConfiguration

expect class KapunIssuance {

	fun initialize()
	fun initialize(networkConfiguration: KapunNetworkConfiguration)
	fun setUntrustedCertificatesAllowed(allow: Boolean)

}
