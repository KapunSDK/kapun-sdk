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
package org.kapunsdk.nfc.apdu

import kotlin.jvm.JvmInline

/**
 * ISO 7816-4 status word (SW1 SW2).
 */
@JvmInline
value class StatusWord(val value: Int) {
	val sw1: Byte get() = (value shr 8).toByte()
	val sw2: Byte get() = value.toByte()

	fun toByteArray() = byteArrayOf(sw1, sw2)

	override fun toString() = value.toString(16).uppercase().padStart(4, '0')

	companion object {
		val SUCCESS = StatusWord(0x9000)
		val WRONG_LENGTH = StatusWord(0x6700)
		val SECURITY_STATUS_NOT_SATISFIED = StatusWord(0x6982)
		val CONDITIONS_NOT_SATISFIED = StatusWord(0x6985)
		val WRONG_DATA = StatusWord(0x6A80)
		val FILE_NOT_FOUND = StatusWord(0x6A82)
		val INCORRECT_P1P2 = StatusWord(0x6A86)
		val INS_NOT_SUPPORTED = StatusWord(0x6D00)
		val CLA_NOT_SUPPORTED = StatusWord(0x6E00)
		val UNKNOWN_ERROR = StatusWord(0x6F00)
	}
}
