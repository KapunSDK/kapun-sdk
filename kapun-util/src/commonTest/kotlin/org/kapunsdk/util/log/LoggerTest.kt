/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.kapunsdk.util.log

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

private data class RecordedLog(
	val severity: LogSeverity,
	val tag: String,
	val message: String,
	val throwable: Throwable?,
)

private class RecordingLogSink : LogSink {
	val recorded = mutableListOf<RecordedLog>()

	override fun log(severity: LogSeverity, tag: String, message: String, throwable: Throwable?) {
		recorded.add(RecordedLog(severity, tag, message, throwable))
	}
}

class LoggerTest {

	@AfterTest
	fun tearDown() {
		// Logger.sink is global state - never leak a test's sink into later tests.
		Logger.sink = null
	}

	@Test
	fun testNoSinkRegisteredProducesNoOutputAndDoesNotThrow() {
		Logger.sink = null

		Logger.debug("hello")
		Logger.info("hello")
		Logger.warn("hello")
		Logger.error("hello")
		Logger.error("hello", IllegalStateException("boom"))
		Logger("CustomTag").debug("hello")
		// If we get here without an exception, the no-sink path is safe.
		assertTrue(true)
	}

	@Test
	fun testDefaultTagAndSeverityAreForwardedToSink() {
		val sink = RecordingLogSink()
		Logger.sink = sink

		Logger.debug("d")
		Logger.info("i")
		Logger.warn("w")
		Logger.error("e")

		assertEquals(4, sink.recorded.size)
		assertEquals(RecordedLog(LogSeverity.DEBUG, "Heidi", "d", null), sink.recorded[0])
		assertEquals(RecordedLog(LogSeverity.INFO, "Heidi", "i", null), sink.recorded[1])
		assertEquals(RecordedLog(LogSeverity.WARN, "Heidi", "w", null), sink.recorded[2])
		assertEquals(RecordedLog(LogSeverity.ERROR, "Heidi", "e", null), sink.recorded[3])
	}

	@Test
	fun testCustomTagIsForwardedToSink() {
		val sink = RecordingLogSink()
		Logger.sink = sink

		Logger("MyTag").warn("careful")

		assertEquals(1, sink.recorded.size)
		assertEquals(LogSeverity.WARN, sink.recorded[0].severity)
		assertEquals("MyTag", sink.recorded[0].tag)
		assertEquals("careful", sink.recorded[0].message)
	}

	@Test
	fun testThrowableIsForwardedOnErrorOnly() {
		val sink = RecordingLogSink()
		Logger.sink = sink
		val exception = IllegalStateException("boom")

		Logger.error("failed", exception)

		assertEquals(1, sink.recorded.size)
		assertEquals(LogSeverity.ERROR, sink.recorded[0].severity)
		assertEquals(exception, sink.recorded[0].throwable)
	}

	@Test
	fun testUnregisteringSinkStopsForwarding() {
		val sink = RecordingLogSink()
		Logger.sink = sink
		Logger.info("seen")
		Logger.sink = null
		Logger.info("not seen")

		assertNull(Logger.sink)
		assertEquals(1, sink.recorded.size)
		assertEquals("seen", sink.recorded[0].message)
	}
}
