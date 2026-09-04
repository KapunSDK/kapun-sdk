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

enum class LogSeverity { DEBUG, INFO, WARN, ERROR }

/**
 * Lets a host app receive log messages produced by this SDK through its own logging pipeline,
 * instead of them always going to a platform console.
 *
 * Register one via `Logger.sink = ...` - typically once at startup, e.g. through
 * `KapunSdk.initialize(logSink = ...)` - before other SDK entry points are called. If no sink is
 * registered, [Logger] produces no output at all; see [platformConsoleLogSink] for a drop-in
 * sink that restores the SDK's previous unconditional console-logging behavior.
 */
interface LogSink {
	fun log(severity: LogSeverity, tag: String, message: String, throwable: Throwable? = null)
}

/**
 * A [LogSink] that reproduces this SDK's previous behavior (unconditional logging to
 * Logcat/os_log/stdout). Not installed by default - pass it to `Logger.sink` or
 * `KapunSdk.initialize(logSink = platformConsoleLogSink())` to opt back into it.
 */
expect fun platformConsoleLogSink(): LogSink
