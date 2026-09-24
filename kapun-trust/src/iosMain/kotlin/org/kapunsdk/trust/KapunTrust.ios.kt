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

package org.kapunsdk.trust

import org.kapunsdk.trust.di.KapunTrustKoinContext
import org.kapunsdk.util.network.KapunNetworkConfiguration

actual class KapunTrust() {

	actual fun initialize() {
		initialize(KapunNetworkConfiguration())
	}

	actual fun initialize(networkConfiguration: KapunNetworkConfiguration) {
		uniffi.kapun_trust_rust.setUntrustedTls(networkConfiguration.allowUntrustedCertificates)
		uniffi.kapun_trust_rust.setUserAgent(networkConfiguration.userAgent)
		uniffi.kapun_util_rust.setUserAgent(networkConfiguration.userAgent)
		KapunTrustKoinContext.initialize(networkConfiguration)
	}

	actual fun setUntrustedCertificatesAllowed(allow: Boolean) {
		uniffi.kapun_trust_rust.setUntrustedTls(allow)
	}

}
