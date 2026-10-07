# kapun-x509
Helper functions for working with x509

## Certificates with external signers

With the `builder` feature, `kapun_x509::builder` exposes:

- `prepare_certificate`: encode the certificate's TBS bytes from DER issuer and
  subject names, SPKI, serial, Unix-second validity, signature algorithm and
  extensions.
- `complete_certificate`: assemble those TBS bytes and a provider signature into
  a DER certificate. Signature bytes use the certificate algorithm's encoding
  (e.g. DER for ECDSA).

Sign the prepared bytes with the issuer's existing key provider, then complete
and verify the certificate before storage. Private keys never enter the builder.
The caller controls CA constraints, usages and other extensions. Invalid DER
and validity ranges return errors. The existing `new_cert` helper is unchanged.

## Managed signing certificates

The opt-in `management` feature exposes owned certificate/name/CSR inspection,
strict PEM/DER serialization, typed construction and offline chain validation.
It encapsulates its Josekit verification backend; callers need no direct
`kapun-crypto` dependency or crypto-provider setup.

Use `prepare_certificate_spec` or `prepare_csr`, sign the returned bytes with an
external provider, then call `complete_certificate_signed` or `complete_csr`.
Completion accepts `SignatureEncoding::JoseRaw` or `Certificate`, converts ECDSA
signatures and verifies the result. Private keys remain outside the builder.

`ChainPolicy` specifies validation time, signing/authority chain kind, required
CA usage, complete/partial/trusted endpoint and optional registered SPKI.
Trusted endpoints require explicit anchors. Validation checks signatures,
validity, issuer names, CA constraints and path length without fetching CRLs.
This API validates ordered signing chains; it does not implement full PKIX path
building, name constraints, certificate policies or revocation checking.

Inspection preserves exact DER, extension values and subject/issuer names.
`encode_name` supports RFC 4514 order or input order for existing platform DNs.
Certificate construction supports CA/leaf roles, usages, SAN, SKI/AKI, CA issuer
AIA, QC types and additional raw extensions. Duplicate extensions are rejected.

The owned management layer delegates to the existing X.509 core. Legacy and
managed APIs share the chain engine, name comparison, basic constraints, key
usage and validity checks. `X509Signer` and external signing share algorithm
identifiers and ECDSA encoding.

## Supplied CRLs

`x509::validate_chain_crls` uses the existing provider interface and shared chain
engine with supplied DER CRLs. It requires a complete or explicitly anchored
chain and current, signed, directly issued full CRLs for every non-anchor
certificate. It checks issuer names, cRLSign usage, update times and revocation
entries. Missing status data fails validation. Delta, scoped and indirect CRLs
are unsupported; unrecognized critical extensions fail validation.

The checks are offline and available without the network `crl` feature.
`validate_chain_crls_with` accepts certificate and CRL verification callbacks.
The NIST 1.07 regression suite passes 56 enabled cases, including all 19 CRL
cases; name-constraint and policy cases remain outside the enabled subset.
