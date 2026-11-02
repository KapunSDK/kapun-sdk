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
package org.kapunsdk.nfc

import org.kapunsdk.nfc.apdu.CommandApdu
import org.kapunsdk.nfc.apdu.ResponseApdu
import org.kapunsdk.nfc.apdu.StatusWord

/**
 * Routes raw command APDUs to the [ApduHandler] selected via SELECT by AID.
 * Never throws: malformed input and handler failures are mapped to error status words.
 */
class ApduDispatcher(private val handlers: List<ApduHandler>) {

	private var selected: ApduHandler? = null

	fun process(commandApdu: ByteArray): ByteArray {
		val command = CommandApdu.parse(commandApdu) ?: return ResponseApdu(StatusWord.WRONG_LENGTH).toByteArray()
		val response = try {
			if (command.isSelectByAid) select(command) else dispatch(command)
		} catch (e: Exception) {
			ResponseApdu(StatusWord.UNKNOWN_ERROR)
		}
		return response.toByteArray()
	}

	fun reset(reason: DeselectReason) {
		selected?.onDeselected(reason)
		selected = null
	}

	private fun select(command: CommandApdu): ResponseApdu {
		val handler = handlers.firstOrNull { it.aid.contentEquals(command.data) }
		if (handler == null) {
			// Per ISO 7816-4, a failed SELECT leaves the current selection untouched
			return ResponseApdu(StatusWord.FILE_NOT_FOUND)
		}
		if (selected != null && selected !== handler) {
			reset(DeselectReason.OTHER_APPLICATION_SELECTED)
		}
		selected = handler
		return handler.onSelected(command)
	}

	private fun dispatch(command: CommandApdu): ResponseApdu {
		val handler = selected ?: return ResponseApdu(StatusWord.CONDITIONS_NOT_SATISFIED)
		return handler.process(command)
	}
}
