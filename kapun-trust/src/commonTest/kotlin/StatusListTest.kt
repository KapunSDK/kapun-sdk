package org.kapunsdk.trust.revocation

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import uniffi.kapun_issuance_rust.StatusList

class StatusListTest {
	@Test
	fun swissStatusListIndexThreeIsNotRevoked() {
		val statusList = StatusList(
			bits = 2u,
			lst = "eNrtwQEBAAAAASD-nzZE1QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwYw1AAAg",
		)

		assertTrue(statusList.isRevoked(0))
		assertFalse(statusList.isRevoked(3))
	}
}
