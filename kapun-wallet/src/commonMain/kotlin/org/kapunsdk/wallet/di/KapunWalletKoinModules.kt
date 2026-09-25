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

package org.kapunsdk.wallet.di

import org.kapunsdk.wallet.credentials.di.credentialsModule
import org.kapunsdk.wallet.crypto.di.cryptoModule
import org.kapunsdk.wallet.database.di.databaseModule
import org.kapunsdk.wallet.keyvalue.di.keyValueModule
import org.kapunsdk.wallet.network.di.networkModule
import org.kapunsdk.wallet.process.legacy.di.processesModule
import org.kapunsdk.wallet.resources.di.resourcesModule
import org.kapunsdk.wallet.trust.TrustAnchorRepository
import org.kapunsdk.wallet.DEFAULT_DATABASE_NAME
import org.kapunsdk.util.network.KapunNetworkConfiguration
import org.koin.core.KoinApplication

fun KoinApplication.kapunWalletModules(
	databaseName: String = DEFAULT_DATABASE_NAME,
	networkConfiguration: KapunNetworkConfiguration = KapunNetworkConfiguration(),
) {
	modules(
		cryptoModule(),
		databaseModule(databaseName),
		networkModule(networkConfiguration),
		keyValueModule(),
		TrustAnchorRepository.koinModule,
		resourcesModule(),
		credentialsModule(),
		processesModule(),
	)
}
