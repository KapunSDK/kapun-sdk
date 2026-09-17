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

package org.kapunsdk.trust.framework

interface TrustAnchorProvider<T> {
    fun isTrusted(param: T): Boolean

    /**
     * Reports a trust anchor encountered while resolving a trust chain that is
     * not currently trusted. Implementations may ignore this hook.
     */
    fun onInvalidTrustAnchor(param: T) = Unit

    /** Adds a trust anchor after explicit user approval. Implementations may ignore this hook. */
    fun addTrustAnchor(param: T) = Unit

    /** Returns anchors configured by this provider, if it supports anchor management. */
    fun getTrustAnchors(): List<T> = emptyList()

    /** Returns anchors added by the user, if it supports anchor management. */
    fun getUserTrustAnchors(): List<T> = emptyList()

    /** Removes a user-managed trust anchor. Implementations may ignore this hook. */
    fun removeTrustAnchor(param: T) = Unit
}
