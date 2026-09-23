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

package org.kapunsdk.proximity.protocol.mdl

import org.kapunsdk.util.extensions.asBoolean
import org.kapunsdk.util.extensions.asBytes
import org.kapunsdk.util.extensions.asLong
import org.kapunsdk.util.extensions.get
import org.kapunsdk.util.extensions.toCbor
import uniffi.kapun_util_rust.decodeCbor
import uniffi.kapun_util_rust.encodeCbor

data class MdlSessionData(
	val data: ByteArray?,
	val status : Long?,
	val shaSum: ByteArray?,
	val dcApiSelected: Boolean? = false
) {
	fun asCbor(): ByteArray {
		return encodeCbor(mapOf(
			"data" to data,
			"status" to status,
			"shaSum" to shaSum,
			"dcApiSelected" to (dcApiSelected ?: false),
		).toCbor())
	}

    companion object {
        fun fromCbor(data: ByteArray) : MdlSessionData? {
            val decoded = runCatching { decodeCbor(data) }.getOrNull() ?: return null
            val data = decoded.get("data").asBytes()
            val status = decoded.get("status").asLong()
            val shaSum = decoded.get("shaSum").asBytes()
			val dcApiSelected = decoded.get("dcApiSelected").asBoolean()
            if(status == null && data == null) {
                return null
            }
            return MdlSessionData(data, status, shaSum, dcApiSelected)
        }
    }
}
