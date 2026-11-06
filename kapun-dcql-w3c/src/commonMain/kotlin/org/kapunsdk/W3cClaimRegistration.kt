/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package org.kapunsdk

import org.kapunsdk.credentials.registerInvalidAndUndisclosableClaims as registerSdJwtClaims

/** Registers additional illegal and undisclosable claims for SD-JWT parsing in this module. */
public fun registerInvalidAndUndisclosableClaims(
	illegalClaims: List<String> = emptyList(),
	undisclosableClaims: List<String> = emptyList(),
) {
	registerSdJwtClaims(illegalClaims, undisclosableClaims)
	uniffi.kapun_dcql_w3c_rust.registerInvalidAndUndisclosableClaims(
		illegalClaims,
		undisclosableClaims,
	)
}
