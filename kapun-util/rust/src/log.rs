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

//! Logging facilities shared by every crate in this workspace.
//!
//! By default nothing is logged: a host app registers a [LogSink] (typically once, at startup,
//! e.g. via the Kotlin `KapunSdk.initialize(logSink = ...)`) to receive these messages through
//! its own logging pipeline. Without a registered sink, `log(...)` and the `log_*!` macros are
//! no-ops.

use std::sync::{Arc, Mutex, OnceLock};

pub const LOG_TAG_FIDO_CLIENT: &str = "Rust_FidoClient";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum LogPriority {
    UNKNOWN = 0,
    DEFAULT,
    VERBOSE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL,
    SILENT,
}

/// Receives log messages produced by this SDK. Implement this on the host side (Kotlin/Swift)
/// and register it once via [register_log_sink] - typically from `KapunSdk.initialize`.
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait LogSink: Send + Sync {
    fn log(&self, priority: LogPriority, tag: String, message: String);
}

fn sink_slot() -> &'static Mutex<Option<Arc<dyn LogSink>>> {
    static SINK: OnceLock<Mutex<Option<Arc<dyn LogSink>>>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(None))
}

/// Registers the [LogSink] that receives every subsequent `log(...)`/`log_*!` call from this
/// process, replacing any previously registered one.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn register_log_sink(sink: Arc<dyn LogSink>) {
    *sink_slot().lock().unwrap() = Some(sink);
}

/// Unregisters the current [LogSink], if any; subsequent log calls become no-ops again.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn clear_log_sink() {
    *sink_slot().lock().unwrap() = None;
}

#[macro_export]
macro_rules! log_warn {
    ($tag:expr, $msg:expr) => {
        $crate::log::log($crate::log::LogPriority::WARN, $tag, $msg);
    };
}

#[macro_export]
macro_rules! log_error {
    ($tag:expr, $msg:expr) => {
        $crate::log::log($crate::log::LogPriority::ERROR, $tag, $msg);
    };
}

#[macro_export]
macro_rules! log_debug {
    ($tag:expr, $msg:expr) => {
        $crate::log::log($crate::log::LogPriority::DEBUG, $tag, $msg);
    };
}

/// Forwards a log message to the registered [LogSink], if any; otherwise a no-op.
pub fn log(priority: LogPriority, tag: &str, text: &str) {
    if let Some(sink) = sink_slot().lock().unwrap().as_ref() {
        sink.log(priority, tag.to_string(), text.to_string());
    }
}
