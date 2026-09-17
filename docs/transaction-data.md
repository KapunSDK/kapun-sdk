# Transaction data and OpenID 1.0

This change retires the legacy POTENTIAL and QES-specific presentation flows. It
retains reusable support for the **OpenID4VP 1.0 SD-JWT transaction-data hash
profile**, not every possible transaction-data profile.

## Breaking changes and migration

- `SpecVersion`, `PotentialUc5`, and `Oid4VpDraft23` are removed. Call
  `withTransactionData(encodedEntries)` without a version argument. Kotlin
  `getVpToken` helpers likewise no longer take `specVersion`.
- `TransactionDataWrapper.UC5`, the `qes_authorization` and
  `qcert_creation_acceptance` models, document-location/digest models, and the
  dedicated QES UI steps are removed. The incorrect legacy document-hash
  validator is removed with them, rather than retained as a general hash API.
- Generic `TransactionData` now contains `type`, `credentialIds`, and the complete
  decoded JSON `payload`. The original encoded string is retained separately.
- `getForCredential(id)` is replaced by
  `selectForCredentials(selectedQueryIds)`. Each transaction is assigned to one
  eligible selected query; unrelated credentials do not receive its hash. The
  caller must select one actual credential for each assigned query, even when
  a DCQL query permits multiple credentials, and verify that it supports holder binding.
- Regenerate UniFFI bindings and rebuild consuming applications together with the
  native libraries. This is not binary-compatible with the removed enum.

## Supported application integration

The built-in wallet no longer has a transaction-type-specific consent UI. It
therefore rejects requests containing transaction data with
`invalid_transaction_data`; it does not silently continue with an ordinary
presentation. No QES or CSC transaction types are enabled by default.

Applications implementing their own type-specific consent flow can pass an
explicit `Map<String, TransactionDataProfile>` to
`PresentationRequest.fromValue` or `TransactionDataWrapper.fromValue`. A profile
specifies its permitted additional field names and a validator that must reject
missing required fields, incorrect types, and invalid values. Opting in also
means that the type explicitly uses the SD-JWT hash profile in Appendix B.3.3.1.
The application must display and obtain consent for the validated transaction,
select a matching credential, and pass only that credential's assigned encoded
entries to the SD-JWT builder. Successful parsing alone is not authorization.

The generic parser checks the standard envelope, DCQL references, cryptographic
holder-binding requirements, unknown fields, and permitted hash algorithms. The
builder independently checks the envelope and supported algorithms, and refuses
to build an unbound response. It cannot validate application-specific schemas,
credential selection, or user consent: those remain the caller's responsibility.

Only SHA-256 is implemented for this profile. It is the required default and is
accepted only when permitted by every supplied algorithm list. Hashes are over
the original base64url strings, without decoding/re-encoding or normalizing JSON.
The builder emits `transaction_data_hashes` and `transaction_data_hashes_alg` in
the signed key-binding JWT. CSC profiles with other output claims or processing
rules require separate implementations; renaming an old QES type is insufficient.

## Specification basis and tests

- [OpenID4VP 1.0 Final §5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.1):
  non-empty transaction array, typed JSON envelope, `credential_ids`, exactly one
  eligible authorizing credential, and rejection of any invalid/unknown type.
- [§8.4–8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.4):
  bind the transaction in the response or return an error; use
  `invalid_transaction_data` for invalid data.
- [§B.3.3–B.3.3.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-B.3.3):
  cryptographic holder binding and the optional SD-JWT hash profile. Tests cover
  the compact §5.1 example with a fixed independently calculated SHA-256 vector,
  multiple entries, algorithm negotiation, and missing holder binding.
- [OpenID4VCI 1.0 Final §4.1.1 and §6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#section-4.1.1):
  issuance `tx_code` is a separate concept and is retained. Tests use the final
  credential-offer example and distinguish an empty `tx_code` object from an
  absent one. An empty object still requires the code in the token request.
  Issuance `transaction_id` identifies deferred issuance (§8.3/§9), not a VP
  authorization payload, and is also retained.

The examples and negative cases are unit-level regression coverage, not a claim
of full OpenID conformance certification.
