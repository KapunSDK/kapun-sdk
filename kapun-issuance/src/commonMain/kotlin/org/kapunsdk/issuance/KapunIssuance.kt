package org.kapunsdk.issuance

import org.kapunsdk.util.network.KapunNetworkConfiguration

expect class KapunIssuance {

	fun initialize(networkConfiguration: KapunNetworkConfiguration = KapunNetworkConfiguration())
	fun setUntrustedCertificatesAllowed(allow: Boolean)

}
