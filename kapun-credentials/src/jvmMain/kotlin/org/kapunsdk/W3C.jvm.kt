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

package org.kapunsdk.credentials

import kotlinx.coroutines.runBlocking

/**
 * Blocking adapter over [W3C.OpenBadge303.parse], for Java callers that cannot invoke a suspend
 * function without driving its Continuation by hand. This is interop only — verification itself
 * still happens in [W3C.OpenBadge303.parse].
 *
 * Deliberately JVM-only: parsing dereferences the Open Badges JSON-LD contexts and the proof's
 * verification method over HTTP, so blocking is acceptable on a thread-per-request server but
 * would freeze the main thread on Android/iOS. Those targets only see the suspend variant.
 */
object OpenBadge303Blocking {
    @JvmStatic
    fun parse(credential: String): W3C.OpenBadge303 =
        runBlocking { W3C.OpenBadge303.parse(credential.encodeToByteArray()) }
}
