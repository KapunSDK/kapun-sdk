package org.kapunsdk

import uniffi.kapun_dcql_rust.ClaimsQuery

data class InvalidClaimsQuery(val claim: ClaimsQuery) : Exception("Invalid claims query")
