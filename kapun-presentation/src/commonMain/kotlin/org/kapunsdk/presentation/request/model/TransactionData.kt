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

package org.kapunsdk.presentation.request.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** A validated OpenID4VP transaction using the SD-JWT SHA-256 hash profile. */
@Serializable
data class TransactionData(
    val type: String,
    val credentialIds: List<String>,
    val payload: JsonObject,
)

/**
 * Explicit opt-in to a transaction type's SD-JWT hash profile. The validator must
 * check all type-specific values and required fields. The caller must render the
 * transaction and obtain consent before presenting it. CSC custom bindings are
 * not implicitly supported by this profile.
 */
class TransactionDataProfile(
    val allowedFields: Set<String>,
    val validate: (JsonObject) -> Unit,
)

class InvalidTransactionDataException(message: String) : IllegalArgumentException(message) {
    val code: String = "invalid_transaction_data"
}
