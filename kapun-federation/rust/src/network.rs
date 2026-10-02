/* Copyright 2026 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations
under the License.
 */

/// OpenID Federation requests with normal TLS verification enabled.
pub struct SdkDefaultConfig;

/// OpenID Federation requests with TLS verification disabled.
pub struct SdkNoVerifyConfig;

impl openid_federation::FetchConfig for SdkDefaultConfig {
    const VERIFY_TLS: bool = true;

    fn user_agent() -> Option<String> {
        kapun_util_rust::network::user_agent()
    }
}

impl openid_federation::FetchConfig for SdkNoVerifyConfig {
    const VERIFY_TLS: bool = false;

    fn user_agent() -> Option<String> {
        kapun_util_rust::network::user_agent()
    }
}
