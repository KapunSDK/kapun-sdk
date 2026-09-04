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
@file:OptIn(ExperimentalForeignApi::class)

package org.kapunsdk.util.log

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ptr
import platform.darwin.*

actual fun platformConsoleLogSink(): LogSink = object : LogSink {
	override fun log(severity: LogSeverity, tag: String, message: String, throwable: Throwable?) {
		val osLogType = when (severity) {
			LogSeverity.DEBUG -> OS_LOG_TYPE_DEBUG
			LogSeverity.INFO -> OS_LOG_TYPE_INFO
			LogSeverity.WARN -> OS_LOG_TYPE_DEFAULT
			LogSeverity.ERROR -> OS_LOG_TYPE_ERROR
		}
		val fullMessage = if (throwable != null) {
			"$message / Exception: ${throwable.message ?: throwable::class.simpleName}"
		} else {
			message
		}
		_os_log_internal(
			__dso_handle.ptr,
			OS_LOG_DEFAULT,
			osLogType,
			"%{public}s",
			fullMessage
		)
	}
}
