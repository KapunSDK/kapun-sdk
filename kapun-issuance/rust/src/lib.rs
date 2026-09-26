/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

pub mod jwt;

kapun_util_rust::export_log_sink_bridge!();

/// Set the user-agent in this native library's private kapun-util copy.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn set_user_agent(user_agent: Option<String>) {
    kapun_util_rust::network::set_user_agent(user_agent);
}

#[doc(hidden)]
#[inline(never)]
pub fn uniffi_link_anchor() -> u8 {
    3
}

#[cfg(target_arch = "arm")]
#[used]
static _KEEP_EH_FRAME_STUBS: [unsafe extern "C" fn(*const u8); 2] = [
    kapun_util_rust::__register_frame,
    kapun_util_rust::__deregister_frame,
];

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
