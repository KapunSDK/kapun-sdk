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

package org.kapunsdk.trust.did

private const val DECENTRALIZED_IDENTIFIER_PREFIX = "decentralized_identifier:"

internal fun getDidFromAbsoluteKid(kid: String): String? {
	val normalizedKid = kid.removePrefix(DECENTRALIZED_IDENTIFIER_PREFIX)
	val parts = normalizedKid.split('#', limit = 2)
	if (parts.size != 2 || parts[0].isBlank() || parts[1].isBlank() || parts[1].contains('#')) {
		return null
	}
	return parts[0].takeIf { it.startsWith("did:") }
}
