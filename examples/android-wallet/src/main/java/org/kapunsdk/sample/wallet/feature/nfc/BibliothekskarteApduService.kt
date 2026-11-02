package org.kapunsdk.sample.wallet.feature.nfc

import android.util.Log
import org.kapunsdk.nfc.ApduHandler
import org.kapunsdk.nfc.DeselectReason
import org.kapunsdk.nfc.KapunHostApduService
import org.kapunsdk.nfc.apdu.CommandApdu
import org.kapunsdk.nfc.apdu.ResponseApdu
import org.kapunsdk.nfc.apdu.StatusWord

private const val TAG = "KapunHce"

class BibliothekskarteApduService : KapunHostApduService() {

	override fun createHandlers(): List<ApduHandler> = listOf(SampleApduHandler())
}

/**
 * Minimal sample application answering a GET DATA command (INS 0xCA, P1P2 0x0000) with a static payload.
 */
private class SampleApduHandler : ApduHandler {

	// DESfire AID 101010 left-padded with zeros to reach Android's 5-byte minimum HCE AID length.
	override val aid = byteArrayOf(0x00, 0x00, 0x10, 0x10, 0x10)

	override fun onSelected(command: CommandApdu): ResponseApdu {
		Log.d(TAG, "selected, le=${command.le}")
		return ResponseApdu(StatusWord.SUCCESS)
	}

	override fun process(command: CommandApdu): ResponseApdu {
		Log.d(TAG, "command ins=${command.ins.toHex()} p1=${command.p1.toHex()} p2=${command.p2.toHex()}")
		if (command.ins != INS_GET_DATA) return ResponseApdu(StatusWord.INS_NOT_SUPPORTED)
		if (command.p1 != 0x00.toByte() || command.p2 != 0x00.toByte()) return ResponseApdu(StatusWord.INCORRECT_P1P2)
		println("!!!!!!!!! Hello from Kapun")
		return ResponseApdu("Hello from Kapun".encodeToByteArray())
	}

	override fun onDeselected(reason: DeselectReason) {
		Log.d(TAG, "deselected: $reason")
	}

	private fun Byte.toHex() = toUByte().toString(16).padStart(2, '0').uppercase()

	companion object {
		private const val INS_GET_DATA: Byte = 0xCA.toByte()
	}
}