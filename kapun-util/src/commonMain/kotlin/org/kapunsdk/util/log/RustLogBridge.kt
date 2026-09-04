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

import uniffi.kapun_util_rust.LogPriority as RustLogPriority
import uniffi.kapun_util_rust.LogSink as RustLogSink
import uniffi.kapun_util_rust.clearLogSink as clearRustLogSink
import uniffi.kapun_util_rust.registerLogSink as registerRustLogSink

/**
 * Forwards log calls made from Rust (the `log_debug!`/`log_warn!`/`log_error!` macros and
 * `kapun_util_rust::log::log`) into the Kotlin [Logger]'s sink, so a host app that registers a
 * single [LogSink] via [Logger.sink] receives both Kotlin- and Rust-originated SDK log output.
 */
private object RustToKotlinLogSink : RustLogSink {
	override fun log(priority: RustLogPriority, tag: String, message: String) {
		val severity = when (priority) {
			RustLogPriority.DEBUG, RustLogPriority.VERBOSE -> LogSeverity.DEBUG
			RustLogPriority.INFO, RustLogPriority.DEFAULT, RustLogPriority.UNKNOWN -> LogSeverity.INFO
			RustLogPriority.WARN -> LogSeverity.WARN
			RustLogPriority.ERROR, RustLogPriority.FATAL -> LogSeverity.ERROR
			RustLogPriority.SILENT -> return
		}
		Logger.sink?.log(severity, tag, message)
	}
}

/**
 * Bridges Rust-originated SDK logs into [Logger.sink]. Called once from `KapunSdk.initialize`,
 * after `Logger.sink` has been assigned, so both language sides funnel into the same sink.
 */
internal fun bridgeRustLogsToKotlin() {
	registerRustLogSink(RustToKotlinLogSink)
}

/** Stops forwarding Rust-originated logs. */
internal fun unbridgeRustLogs() {
	clearRustLogSink()
}
