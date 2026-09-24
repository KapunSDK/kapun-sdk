/* Copyright 2024 Ubique Innovation AG

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
package org.kapunsdk.wallet.di

import org.koin.core.Koin
import org.koin.core.KoinApplication
import org.koin.dsl.koinApplication
import org.kapunsdk.trust.framework.swiss.SwissTrustConfiguration
import org.kapunsdk.wallet.DEFAULT_DATABASE_NAME

internal object KapunWalletKoinContext {

	private lateinit var koinApp: KoinApplication
	lateinit var koin: Koin

	fun initialize(
		databaseName: String = DEFAULT_DATABASE_NAME,
		swissTrustConfiguration: SwissTrustConfiguration = SwissTrustConfiguration(),
		declaration: KoinApplication.() -> Unit = {},
	) {
		koinApp = koinApplication {
			declaration()
			kapunWalletModules(databaseName, swissTrustConfiguration)
		}
		koin = koinApp.koin
	}
}
