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

/**
 * A parsed ISO 7816-4 command APDU, supporting short and extended length encoding.
 *
 * @property le the expected response length, or null if absent. A zero-encoded Le is expanded to 256 (short) or 65536 (extended).
 */
class CommandApdu(
	val cla: Byte,
	val ins: Byte,
	val p1: Byte,
	val p2: Byte,
	val data: ByteArray = byteArrayOf(),
	val le: Int? = null,
) {
	val isSelectByAid: Boolean
		get() = cla.toInt() and 0x80 == 0 && ins == INS_SELECT && p1 == P1_SELECT_BY_AID

	companion object {
		const val INS_SELECT: Byte = 0xA4.toByte()
		const val P1_SELECT_BY_AID: Byte = 0x04

		/**
		 * Parses the raw [bytes] of a command APDU, returning null if the encoding is malformed.
		 */
		fun parse(bytes: ByteArray): CommandApdu? {
			if (bytes.size < 4) return null
			val cla = bytes[0]
			val ins = bytes[1]
			val p1 = bytes[2]
			val p2 = bytes[3]
			val body = bytes.size - 4

			// Case 1: header only
			if (body == 0) return CommandApdu(cla, ins, p1, p2)

			val b0 = bytes[4].toUnsignedInt()

			// Case 2S: Le only
			if (body == 1) return CommandApdu(cla, ins, p1, p2, le = if (b0 == 0) 256 else b0)

			if (b0 != 0) {
				// Case 3S / 4S: Lc + data (+ Le)
				val lc = b0
				return when (body) {
					1 + lc -> CommandApdu(cla, ins, p1, p2, bytes.copyOfRange(5, 5 + lc))
					2 + lc -> {
						val le = bytes[5 + lc].toUnsignedInt()
						CommandApdu(cla, ins, p1, p2, bytes.copyOfRange(5, 5 + lc), if (le == 0) 256 else le)
					}
					else -> null
				}
			}

			// Extended length: leading 0x00 followed by two length bytes
			if (body < 3) return null
			val len = bytes.readUnsignedShort(5)

			// Case 2E: Le only
			if (body == 3) return CommandApdu(cla, ins, p1, p2, le = if (len == 0) 65536 else len)

			// Case 3E / 4E: Lc + data (+ Le)
			val lc = len
			if (lc == 0) return null
			return when (body) {
				3 + lc -> CommandApdu(cla, ins, p1, p2, bytes.copyOfRange(7, 7 + lc))
				5 + lc -> {
					val le = bytes.readUnsignedShort(7 + lc)
					CommandApdu(cla, ins, p1, p2, bytes.copyOfRange(7, 7 + lc), if (le == 0) 65536 else le)
				}
				else -> null
			}
		}

		private fun Byte.toUnsignedInt() = toInt() and 0xFF

		private fun ByteArray.readUnsignedShort(offset: Int) = (this[offset].toUnsignedInt() shl 8) or this[offset + 1].toUnsignedInt()
	}
}
