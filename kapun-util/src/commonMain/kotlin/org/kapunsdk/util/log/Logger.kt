/* Copyright 2024 Ubique Innovation AG

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

class Logger(val tag: String) {

	companion object {
		private const val DEFAULT_TAG = "Heidi"

		/**
		 * When null (the default), SDK log calls produce no output at all. Set this once, at
		 * startup - typically via `KapunSdk.initialize(logSink = ...)` - to receive them through
		 * your own logging pipeline instead. See [platformConsoleLogSink] to opt back into this
		 * SDK's previous unconditional console-logging behavior.
		 */
		var sink: LogSink? = null

		fun debug(msg: String) = Logger(DEFAULT_TAG).debug(msg)
		fun info(msg: String) = Logger(DEFAULT_TAG).info(msg)
		fun warn(msg: String) = Logger(DEFAULT_TAG).warn(msg)
		fun error(msg: String) = Logger(DEFAULT_TAG).error(msg)
		fun error(msg: String, throwable: Throwable) = Logger(DEFAULT_TAG).error(msg, throwable)
	}

	fun debug(msg: String) = log(LogSeverity.DEBUG, msg)
	fun info(msg: String) = log(LogSeverity.INFO, msg)
	fun warn(msg: String) = log(LogSeverity.WARN, msg)
	fun error(msg: String) = log(LogSeverity.ERROR, msg)
	fun error(msg: String, throwable: Throwable) = log(LogSeverity.ERROR, msg, throwable)

	private fun log(severity: LogSeverity, msg: String, throwable: Throwable? = null) {
		sink?.log(severity, tag, msg, throwable)
	}
}
