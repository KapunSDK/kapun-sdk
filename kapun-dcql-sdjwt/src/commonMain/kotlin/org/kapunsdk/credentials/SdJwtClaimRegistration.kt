/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package org.kapunsdk.credentials

/** Replaces the additional illegal and undisclosable SD-JWT claim names for this module. */
public fun registerInvalidAndUndisclosableClaims(
    illegalClaims: List<String> = emptyList(),
    undisclosableClaims: List<String> = emptyList(),
) {
    uniffi.kapun_dcql_sdjwt_rust.registerInvalidAndUndisclosableClaims(
        illegalClaims,
        undisclosableClaims,
    )
}
