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

use base64::{
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
    Engine,
};

pub mod crypto;
pub mod iso180135;
pub mod jwx;
pub mod jws;
pub mod jwt;

/// This crate compiles to its own native library, statically linking a private copy of
/// `kapun_util_rust::log` - registering a sink via `kapun-util`'s own binding only reaches
/// *that* library, not this one's `log_warn!`/`log_error!`/`log_debug!` call sites. This
/// forwards to this crate's own linked-in copy of the same registration function, so a host app
/// can reach it too. See `kapun-util/rust/src/log.rs` for the full explanation.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn register_log_sink(sink: std::sync::Arc<dyn kapun_util_rust::log::LogSink>) {
    kapun_util_rust::log::register_log_sink(sink);
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn clear_log_sink() {
    kapun_util_rust::log::clear_log_sink();
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum SigningError {
    FailedToSign,
    InvalidSecret,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = BASE64_URL_SAFE_NO_PAD.decode(input) {
        return Some(decoded);
    }
    if let Ok(decoded) = BASE64_URL_SAFE.decode(input) {
        return Some(decoded);
    }
    if let Ok(decoded) = BASE64_STANDARD_NO_PAD.decode(input) {
        return Some(decoded);
    }
    if let Ok(decoded) = BASE64_STANDARD.decode(input) {
        return Some(decoded);
    }
    return None;
}

#[cfg(target_arch = "arm")]
#[used]
static _KEEP_EH_FRAME_STUBS: [unsafe extern "C" fn(); 2] = [
    kapun_util_rust::__register_frame,
    kapun_util_rust::__deregister_frame,
];

uniffi::setup_scaffolding!();
