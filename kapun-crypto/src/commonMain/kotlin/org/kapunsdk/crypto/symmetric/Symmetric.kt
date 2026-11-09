package org.kapunsdk.crypto.symmetric

import uniffi.kapun_crypto_rust.hkdfSha256 as hkdfSha256Raw
import uniffi.kapun_crypto_rust.secureRandomBytes as secureRandomBytesRaw

fun secureRandomBytes(length: Int): ByteArray = secureRandomBytesRaw(length.toUInt())

fun hkdfSha256(
    keyMaterial: ByteArray,
    salt: ByteArray,
    info: ByteArray = byteArrayOf(),
    outputLength: Int = 32,
): ByteArray = hkdfSha256Raw(keyMaterial, salt, info, outputLength.toUInt())
