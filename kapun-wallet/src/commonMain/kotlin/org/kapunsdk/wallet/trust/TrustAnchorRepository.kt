/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the License for the specific language
governing permissions and limitations under the License.
 */

package org.kapunsdk.wallet.trust

import org.kapunsdk.trust.model.TrustAnchorInfo
import org.kapunsdk.wallet.KapunDatabase
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

/** Persists user-added trust anchors in the wallet database. */
class TrustAnchorRepository private constructor(db: KapunDatabase) {

	companion object {
		val koinModule = module {
			singleOf(::TrustAnchorRepository)
		}
	}

	private val queries = db.trustAnchorQueries

	fun getAll() = queries.getAll().executeAsList().map { it.toModel() }

	fun getByFramework(trustFrameworkId: String) =
		queries.getByFramework(trustFrameworkId).executeAsList().map { it.toModel() }

	fun save(trustAnchor: TrustAnchorInfo) = queries.insert(
		trustAnchor.trustFrameworkId,
		trustAnchor.key,
		trustAnchor.subject,
	)

	fun remove(trustAnchor: TrustAnchorInfo) = queries.remove(
		trustAnchor.trustFrameworkId,
		trustAnchor.key,
		trustAnchor.subject,
	)

	fun clear() = queries.clear()

	private fun org.kapunsdk.wallet.TrustAnchorEntity.toModel() = TrustAnchorInfo(
		key = key,
		subject = subject,
		trustFrameworkId = trust_framework_id,
		isRemovable = true,
	)
}
