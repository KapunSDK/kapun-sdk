package org.kapunsdk.nfc

import org.kapunsdk.nfc.apdu.CommandApdu
import org.kapunsdk.nfc.apdu.ResponseApdu
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class ApduDispatcherTest {

	private class RecordingHandler(override val aid: ByteArray, private val payload: ByteArray) : ApduHandler {
		val deselections = mutableListOf<DeselectReason>()

		override fun process(command: CommandApdu): ResponseApdu {
			if (command.ins == 0x00.toByte()) error("boom")
			return ResponseApdu(payload)
		}

		override fun onDeselected(reason: DeselectReason) {
			deselections += reason
		}
	}

	private val first = RecordingHandler(hex("F04B4150554E"), hex("01"))
	private val second = RecordingHandler(hex("F04B415055AA"), hex("02"))
	private val dispatcher = ApduDispatcher(listOf(first, second))

	@Test
	fun selectAndProcess() {
		assertContentEquals(hex("9000"), dispatcher.process(hex("00A4040006F04B4150554E00")))
		assertContentEquals(hex("019000"), dispatcher.process(hex("00CA000000")))
	}

	@Test
	fun unknownAid() {
		assertContentEquals(hex("6A82"), dispatcher.process(hex("00A4040005F000000000")))
	}

	@Test
	fun commandWithoutSelection() {
		assertContentEquals(hex("6985"), dispatcher.process(hex("00CA000000")))
	}

	@Test
	fun malformedCommand() {
		assertContentEquals(hex("6700"), dispatcher.process(hex("00CA")))
	}

	@Test
	fun handlerException() {
		dispatcher.process(hex("00A4040006F04B4150554E"))
		assertContentEquals(hex("6F00"), dispatcher.process(hex("0000000000")))
	}

	@Test
	fun switchingApplicationsDeselectsPrevious() {
		dispatcher.process(hex("00A4040006F04B4150554E"))
		dispatcher.process(hex("00A4040006F04B415055AA"))
		assertEquals(listOf(DeselectReason.OTHER_APPLICATION_SELECTED), first.deselections)
		assertContentEquals(hex("029000"), dispatcher.process(hex("00CA000000")))
	}

	@Test
	fun resetClearsSelection() {
		dispatcher.process(hex("00A4040006F04B4150554E"))
		dispatcher.reset(DeselectReason.LINK_LOSS)
		assertEquals(listOf(DeselectReason.LINK_LOSS), first.deselections)
		assertContentEquals(hex("6985"), dispatcher.process(hex("00CA000000")))
	}
}
