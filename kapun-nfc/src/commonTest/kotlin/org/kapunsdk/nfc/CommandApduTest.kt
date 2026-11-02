package org.kapunsdk.nfc

import org.kapunsdk.nfc.apdu.CommandApdu
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CommandApduTest {

	@Test
	fun case1() {
		val apdu = CommandApdu.parse(hex("00B00000"))!!
		assertEquals(0xB0.toByte(), apdu.ins)
		assertEquals(0, apdu.data.size)
		assertNull(apdu.le)
	}

	@Test
	fun case2ShortWithZeroLe() {
		assertEquals(256, CommandApdu.parse(hex("00B0000000"))!!.le)
	}

	@Test
	fun case3Short() {
		val apdu = CommandApdu.parse(hex("00A4040006F04B4150554E"))!!
		assertContentEquals(hex("F04B4150554E"), apdu.data)
		assertNull(apdu.le)
		assertTrue(apdu.isSelectByAid)
	}

	@Test
	fun case4Short() {
		val apdu = CommandApdu.parse(hex("00A4040006F04B4150554E00"))!!
		assertContentEquals(hex("F04B4150554E"), apdu.data)
		assertEquals(256, apdu.le)
	}

	@Test
	fun case2Extended() {
		assertEquals(65536, CommandApdu.parse(hex("00B00000000000"))!!.le)
		assertEquals(0x0102, CommandApdu.parse(hex("00B00000000102"))!!.le)
	}

	@Test
	fun case3And4Extended() {
		val case3 = CommandApdu.parse(hex("00DA0000000003AABBCC"))!!
		assertContentEquals(hex("AABBCC"), case3.data)
		assertNull(case3.le)

		val case4 = CommandApdu.parse(hex("00DA0000000003AABBCC0010"))!!
		assertContentEquals(hex("AABBCC"), case4.data)
		assertEquals(16, case4.le)
	}

	@Test
	fun malformed() {
		assertNull(CommandApdu.parse(hex("00A404")))
		assertNull(CommandApdu.parse(hex("00A4040006F04B41")))
		assertNull(CommandApdu.parse(hex("00A4040002AABBCCDD")))
		assertNull(CommandApdu.parse(hex("00DA00000000")))
		assertNull(CommandApdu.parse(hex("00DA0000000000AA")))
	}
}

internal fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
