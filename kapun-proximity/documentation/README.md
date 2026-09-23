# Proximity documentation generator

This small Rust package generates the includeable proximity data, narrative, and focused inline code samples. It lives under
`kapun-proximity` so the examples stay beside the Kotlin wire models, while validation uses the
existing `kapun-pdf-rust` Typst world.

The documents are intentionally split:

- `proximity-data.typ` contains the includeable `proximity_models`, `proximity_examples`, and
  `proximity_flow` values, as well as their JSON strings. Each example has a stable `id`, and
  each flow step points to its payload with `example_ref`.
- `proximity-text.typ` contains the adapted source document and references those values without
  redefining them.
- `proximity-flow-graph.typ` contains the reusable CeTZ graph function.
- `proximity-code.typ` contains short, source-line-cited Kotlin and Rust excerpts, styled with
  Codly and highlighting the protocol operation described nearby in the narrative. The snippets
  are included inline; complete implementation files are not copied into the output directory.
  TODO comments are blanked in the displayed excerpts while their line breaks are retained, so
  Codly's `offset` and highlight still refer to the original source. Executable `TODO(...)` calls
  and string literals are preserved. Repeated excerpts use distinct labels per walkthrough.
- `session_encryption.typ` contains the separate session-encryption section; the generated
  narrative includes it. `diag-notation.typ` and its Sublime syntax definition provide the shared
  notation renderer and the payload/code wrapping helper.
- `proximity.typ` is a ready-to-compile wrapper that includes all three files.
- `proximity-models.json`, `proximity-examples.json`, and `proximity-flow.json` are exact JSON
  sidecars for tooling and copy/paste. The printed Typst appendix abbreviates only long byte
  strings; the sidecars preserve every value exactly.

Generate both files:

```sh
cargo run -p kapun-proximity-docgen -- --output-dir ./generated
```

To produce a PDF with an installed Typst CLI:

```sh
typst compile generated/proximity.typ generated/proximity.pdf
```

The narrative uses 10 pt body text, full-width model tables, and 8.5 pt source and payload text.
Each individual model table stays together; a recursively resolved bundle can span pages as one
figure. A relevant test element follows each bundle, with the full record linked in the appendix.
CBOR diagnostic notation retains operators and tags and indents map/array members by two spaces.
Long payloads use the shared `autobreaking` helper; model and JSON content is left aligned.

To append the labelled Kotlin/JVM test vectors to the Rust-generated examples, run the Gradle
test from the Rust generator and parse its `PROXIMITY_DOC[...]` output:

```sh
cargo run -p kapun-proximity-docgen -- --include-kotlin-examples --output-dir ./generated
```

This keeps the Rust vectors and adds `kotlin_*` example IDs. Each flow test verifies its own first
message and executes payload → encryption → CBOR encode/decode → decryption → payload assertions.
The generator requires both flow markers, parses all emitted CBOR, and checks the response
`shaSum`. Kotlin ephemeral private keys are intentionally not exported, so Rust does not attempt to
decrypt those random-key ciphertexts a second time.

`--validate` uses the in-repo Typst renderer. Its `CACHE_DIRECTORY` environment variable may point
at an existing Typst package cache so CeTZ and Codly are reused without a second download.

Include the data in another Typst document, optionally followed by the generated narrative:

```typst
#import "generated/proximity-data.typ": *
#import "generated/proximity-flow-graph.typ": proximity_flow_graph

// The values can now be mapped into your own tables, figures, or prose:
// proximity_models, proximity_examples, proximity_flow

#include "generated/proximity-text.typ"
```

Or compile `generated/proximity.typ` directly. The graph implementation is independent of the
generated payloads and can be included by other documents that provide their own `steps` tuple.
Wire steps supply `sender` and `receiver` (`"wallet"` or `"reader"`); local computation steps may
instead supply `local_actors: ("wallet", "reader")` to draw self-action arrows on each lifeline.
Every step supplies an `action` and an `example_ref`; use `line_style: "dashed"` for internal
cryptographic or authentication milestones that are not wire messages. This produces a
PlantUML-like two-lane diagram with the wallet/device on the left, the verifier/reader on the right,
and either cross-lane message arrows or local self-action arrows.
The renderer splits longer sequences into panels of at most three steps and repeats the actor
headers, allowing page breaks between panels. `steps-per-panel` controls the grouping. Omit
`example_ref` and `trace_ref` when using the renderer without this document's appendix.
The primary normal/reverse walkthroughs embed one-step panels beside the relevant guidance,
focused code, exact bytes, and round-trip checks. ECDH and reader authentication use local arrows.

Validate the combined source with the Kapun Typst renderer:

```sh
cargo run -p kapun-proximity-docgen -- --validate --output-dir ./generated
```

For pipelines, `--data-output PATH` and `--text-output PATH` write either document separately.
With no output option, the command prints the includeable data document to stdout.

The generated data includes recursively resolved model bundles (each grouped as one figure, with a
labelled test sample directly below), model-to-wire mappings, and examples for ReaderEngagement,
DeviceEngagement, encoded SessionEstablishment/SessionData, P-256 ECDH public keys, the
documentation-only private scalars, the ECDH-derived key material (`Z_ab`) used as HKDF input,
role-separated HKDF keys, the session transcript, origin, and AES-GCM ciphertexts. It has separate end-to-end examples for the normal
flow (scan DeviceEngagement, then receive SessionEstablishment) and the reverse flow (scan
ReaderEngagement, then receive DeviceEngagement as the first application message). The flow trace
also covers the Swiss-profile verifier-attestation decision boundary. Every graph edge references
an appendix payload figure and a labelled trace figure; trace records link to the corresponding
highlighted inline implementation excerpts. Exact payload JSON remains available in the sidecar
even when a printed card abbreviates long byte strings.

The Kotlin vectors are labelled documentation tests and print fresh payloads from the SDK:

```sh
./gradlew :kapun-proximity:jvmTest --tests '*ProximityDocumentationVectorTest*'
```

Their output lines begin with `PROXIMITY_DOC[...]`, which makes it possible to capture them before
building the main Typst document. The generator forwards Gradle output live to stdout and prints
its own phase markers to stderr, so a long first run is observable in CI and local terminals. The
`shaSum` field is retained in the examples as the existing
Swiss/debug extension; it is not presented as part of the generic ISO SessionData model.
