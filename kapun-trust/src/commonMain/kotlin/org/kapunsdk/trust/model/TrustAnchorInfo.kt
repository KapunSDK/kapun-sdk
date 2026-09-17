/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

package org.kapunsdk.trust.model

import kotlinx.serialization.Serializable

/**
 * Details about a trust anchor that was found in a resolved trust chain but is
 * not currently trusted by the wallet.
 */
@Serializable
data class TrustAnchorInfo(
	val key: String,
	val subject: String,
	val trustFrameworkId: String,
	/** Whether the anchor was added by the user and can be removed. */
	val isRemovable: Boolean = true,
)
