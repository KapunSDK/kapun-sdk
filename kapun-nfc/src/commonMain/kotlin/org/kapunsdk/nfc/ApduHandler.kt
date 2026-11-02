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
 * An emulated card application, identified by its [aid]. Once selected by the reader, all subsequent
 * command APDUs are routed to [process] until another application is selected or the link is lost.
 */
interface ApduHandler {
	val aid: ByteArray

	/**
	 * Called when the reader selects this application. The returned response is sent as answer to the SELECT command.
	 */
	fun onSelected(command: CommandApdu): ResponseApdu = ResponseApdu(StatusWord.SUCCESS)

	fun process(command: CommandApdu): ResponseApdu

	fun onDeselected(reason: DeselectReason) {}
}

enum class DeselectReason {
	/** The NFC link was lost, e.g. the device was removed from the reader field. */
	LINK_LOSS,

	/** The reader selected an AID that is routed to a different service. */
	DESELECTED,

	/** The reader selected another application handled by the same dispatcher. */
	OTHER_APPLICATION_SELECTED,
}
