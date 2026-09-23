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

package org.kapunsdk.util.network

import io.ktor.client.HttpClient

/**
 * Network dependencies and security policy supplied by the host application.
 *
 * The SDK does not close [httpClient]. The host remains responsible for its lifecycle.
 * When [httpClient] is null, [userAgent] is applied to the SDK-created Ktor client. Rust-owned
 * clients use the same value through the platform bindings.
 */
class KapunNetworkConfiguration(
	val httpClient: HttpClient? = null,
	val allowUntrustedCertificates: Boolean = false,
	val userAgent: String? = null,
)
