/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package org.kapunsdk.wallet

import org.kapunsdk.registerInvalidAndUndisclosableClaims as registerW3cClaims

/**
 * Replaces the additional illegal and undisclosable claim lists in the SD-JWT parser copies used
 * by the standalone SD-JWT, W3C, and wallet native components.
 */
public fun registerInvalidAndUndisclosableClaims(
	illegalClaims: List<String> = emptyList(),
	undisclosableClaims: List<String> = emptyList(),
) {
	registerW3cClaims(illegalClaims, undisclosableClaims)
	uniffi.kapun_wallet_rust.registerInvalidAndUndisclosableClaims(
		illegalClaims,
		undisclosableClaims,
	)
}
