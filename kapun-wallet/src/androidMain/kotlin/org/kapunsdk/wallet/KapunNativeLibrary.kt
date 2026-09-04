/* Copyright 2026 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
*/

package org.kapunsdk.wallet

/** Configures UniFFI component bindings to use the wallet's aggregate Android library. */
internal object KapunNativeLibrary {
	private const val WALLET_LIBRARY = "kapun_wallet_rust"

	private val bundledComponents = listOf(
		"kapun_util_rust",
		"kapun_crypto_rust",
		"kapun_credential_core_rust",
		"kapun_dcql_rust",
		"kapun_dcql_bbs_rust",
		"kapun_dcql_mdoc_rust",
		"kapun_dcql_sdjwt_rust",
		"kapun_dcql_w3c_rust",
		"kapun_dcql_openbadges_rust",
		"kapun_issuance_rust",
		"kapun_presentation_rust",
		"kapun_trust_rust",
	)

	fun configure() {
		bundledComponents.forEach { component ->
			System.setProperty("uniffi.component.$component.libraryOverride", WALLET_LIBRARY)
		}
	}
}
