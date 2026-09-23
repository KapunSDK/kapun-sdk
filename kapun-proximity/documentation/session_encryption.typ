== Session Encryption (ISO 18013-5)

1. The wallet generates `DeviceEngagement`, including the public key of its ephemeral key pair.
2. The Check App generates its ephemeral key pair. Both peers compute the same ECDH shared secret:
   `ECDH(EDeviceKey.Priv, EReaderKey.Pub)` at the wallet and
   `ECDH(EDeviceKey.Pub, EReaderKey.Priv)` at the Check App.
3. Each peer derives `SKReader` and `SKDevice` from the shared secret and the session transcript.
   The Check App encrypts requests with `SKReader`; the wallet encrypts responses with `SKDevice`.

== Kapun Key Derivation

- ECDH: P-256 ECKA-DH produces the shared secret `Z_ab`.
- The ECDH result `Z_ab` is the key material passed into HKDF as its input key material (IKM):
  `HKDF-Extract(SHA-256(SessionTranscriptBytes), Z_ab)`. In the generated vectors this value is
  exposed as `key_material_hex` and is the same on both peers.
- HKDF-SHA-256 uses `Z_ab` as the input key material and
  `SHA-256(SessionTranscriptBytes)` as the salt. `SessionTranscriptBytes` is the CBOR encoding of
  tag 24 containing the CBOR-encoded `SessionTranscript` (`[ #6.24(bstr .cbor DeviceEngagement),
  #6.24(bstr .cbor EReaderKey), null ]`).
- The SDK derives both keys from that same salt, using the UTF-8 role label as HKDF `info`:
  `SKReader = HKDF-Expand(PRK, "SKReader", 32)` and
  `SKDevice = HKDF-Expand(PRK, "SKDevice", 32)`, where `PRK` is the HKDF-SHA-256 extract result
  for salt `SHA-256(SessionTranscriptBytes)` and IKM `Z_ab`. Each key is 32 bytes (256 bits).
  The Check App encrypts requests with `SKReader`; the wallet encrypts responses with `SKDevice`.
- Encryption: AES-256-GCM uses an empty AAD. The nonce is `identifier | count`, where `|` is byte
  concatenation. The Check App identifier is eight zero bytes; the wallet identifier is
  `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]`. The counter is independent for each key,
  starts at `1`, and is a four-byte big-endian integer. The encrypted message is
  `ciphertext | 16-byte authentication tag`.
