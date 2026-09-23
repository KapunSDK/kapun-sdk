#import "proximity-data.typ": *
#import "proximity-flow-graph.typ": proximity_flow_graph
#import "@preview/tiaoma:0.3.0"
#import "@preview/based:0.2.0": base64
#import "@preview/codly:1.3.0": *
#show: codly-init.with()
#codly(languages: (
  kotlin: (name: "Kotlin", color: rgb("#7f52ff")),
  rust: (name: "Rust", color: rgb("#b7410e")),
))
#import "diag-notation.typ": autobreaking, diag-notation
#import "proximity-code.typ": proximity-code-sample


// The generated data module defines proximity_models, proximity_examples, proximity_flow,
// proximity_models_json, proximity_examples_json, and proximity_flow_json. Import it with `*`,
// and import proximity_flow_graph from proximity-flow-graph.typ before including this file.

#set page(paper: "a4", margin: (x: 20mm, top: 20mm, bottom: 21mm),
  header: [#text(size: 8pt, fill: rgb("64748b"))[KAPUN SDK #h(1fr) PROXIMITY / IMPLEMENTER GUIDE]],
  footer: context [#text(size: 8pt, fill: rgb("64748b"))[ISO 18013-5 #h(1fr) #counter(page).display("1")]],
)
#set text(font: "Helvetica Neue", size: 10pt, fill: rgb("1e293b"))
#set par(justify: false, leading: 0.65em)
#set heading(numbering: none)
#show raw: set text(font: "DejaVu Sans Mono", size: 8.5pt)
#set table(inset: 6pt, align: left + top,
  stroke: (paint: rgb("e2e8f0"), thickness: 0.4pt))
#show heading.where(level: 1): set text(size: 25pt, fill: rgb("0f172a"))
#show heading.where(level: 2): set text(size: 17pt, fill: rgb("0f172a"))
#show heading.where(level: 3): set text(size: 13pt, fill: rgb("087f8c"))
#show heading.where(level: 4): set text(size: 11pt, fill: rgb("4f46e5"))
#show heading.where(level: 5): set text(size: 10pt)
#show figure: set block(breakable: true)
#show figure.where(kind: "code"): set block(breakable: false)
#show figure.caption: set text(size: 8pt, fill: rgb("64748b"))
#show link: set text(fill: rgb("4f46e5"))

#let callout(title, body) = block(width: 100%, breakable: true,
  fill: rgb("eef6f7"), stroke: (left: 2pt + rgb("087f8c")), inset: 11pt)[
  #text(weight: "bold", fill: rgb("087f8c"))[#title]
  #parbreak()
  #body
]

#let json-card-content(example) = block(
  width: 100%,
  breakable: true,
  fill: luma(97%),
  stroke: (paint: luma(82%), thickness: 0.5pt),
  radius: 0.35em,
  inset: 0.7em,
)[
  #set align(left)
  #text(size: 9pt, weight: "bold", fill: rgb("0f172a"))[#example.id]
  #h(0.35em)
  #text(size: 8pt, fill: rgb("475569"))[#example.name]
  #h(0.45em)
  #parbreak()
  #set text(size: 8pt, font: "DejaVu Sans Mono")
  #autobreaking(raw(example.payload_display_json, lang: "json"))
]

#let json-card(example) = [
  #figure(
    json-card-content(example),
    kind: "figure",
    supplement: [Payload],
    caption: [#text(font: "DejaVu Sans Mono")[#example.id] — #example.name],
  )
  #label("payload-" + example.id)
]

#let breakable-inline(value) = {
  show regex(".+"): s => s.text.codepoints().join(sym.zws)
  value
}

#let model-card(model) = block(width: 100%, breakable: false, above: 10pt, below: 10pt)[
  #set align(left)
  #block(width: 100%, fill: rgb("eef2f8"), inset: 9pt, sticky: true)[
    #text(size: 10pt, weight: "bold", fill: rgb("0f172a"))[#model.name]
    #linebreak()
    #text(size: 8.5pt, fill: rgb("475569"))[#model.encoding]
  ]
  #set text(size: 8.5pt)
  #table(
    columns: (1.2fr, 0.45fr, 1.05fr, 1.5fr),
    align: left + top,
    fill: (x, y) => if y == 0 { rgb("f1f5f9") } else { none },
    table.header([*Field*], [*Label*], [*Encoding*], [*Meaning*]),
    ..model.fields.map(field => (
      [#text(font: "DejaVu Sans Mono", size: 8.5pt)[#breakable-inline(field.name)]],
      [#field.cbor_key],
      [#text(font: "DejaVu Sans Mono", size: 8.5pt)[#breakable-inline(field.wire_type)]],
      [#text(weight: "bold")[#if field.optional { [Optional.] } else { [Required.] }] #field.description],
    )).flatten(),
  )
]

#let model-bundle-figure(bundle) = {
  let resolved = bundle.model_ids.map(id => proximity_models.find(model => model.id == id))
  figure(
    block(width: 100%, breakable: true)[
      #for model in resolved { model-card(model) }
    ],
    kind: "figure",
    supplement: [Model],
    caption: [#bundle.title / Complete Model Family],
  )
}

#let model-example(bundle) = {
  let test-example = if bundle.id in ("swiss_verifier_inputs", "ecdh_key_material") {
    none // These bundles need fields not exported by the Kotlin encryption example.
  } else {
    proximity_examples.find(example => example.id == bundle.kotlin_example_ref)
  }
  let sample = if test-example == none {
    proximity_examples.find(example => example.id == bundle.example_ref)
  } else {
    test-example
  }
  if sample != none {
    let record = json(bytes(sample.payload_json))
    let display = json(bytes(sample.payload_display_json))
    let data = if test-example == none { record } else { record.fields }
    let view = if test-example == none { display } else { display.fields }
    let element = view
    if bundle.id == "dc_api_request" {
      let request = data.at("request_plaintext_utf8", default: data.at("plaintext_request", default: none))
      if request != none {
        element = if type(request) == str { json(bytes(request)) } else { request }
      }
    } else if bundle.id == "session_transcript" {
      element = (session_transcript_outer_hex: view.session_transcript_outer_hex, origin: view.origin)
    } else if bundle.id == "ecdh_key_material" {
      element = (:)
      for key in ("documentation_only_reader_private_scalar_hex", "documentation_only_device_private_scalar_hex",
        "reader_public_key_sec1_hex", "device_public_key_sec1_hex", "key_material_hex", "sk_reader_hex", "sk_device_hex") {
        if key in view { element.insert(key, view.at(key)) }
      }
    } else if bundle.id == "swiss_verifier_inputs" and "fields" in data {
      element = data.fields.decoded_request_claims
    } else if bundle.id in ("reader_engagement", "device_engagement") and "diagnostic" in view {
      element = view.diagnostic
    } else if bundle.id in ("session_establishment", "session_data") and "fields" in view {
      element = (:)
      for key in ("eReaderKey_cbor_hex", "data_ciphertext_hex", "dcApiSelected") {
        if key in view.fields { element.insert(key, view.fields.at(key)) }
      }
    }
    block(sticky: true)[
      #text(size: 9pt, weight: "bold", fill: rgb("334155"))[
        Test Example · #if test-example == none { [Rust] } else { [Kotlin/JVM] }
      ]
      #text(size: 8pt)[ · Full Record: #ref(label("payload-" + sample.id))]
    ]
    block(width: 100%, breakable: true, fill: rgb("f6f8fb"), inset: 10pt, radius: 3pt)[
      #set align(left)
      #autobreaking(raw(json.encode(element, pretty: true), lang: "json"))
    ]
  }
}

#let include-model-bundle(id) = {
  let bundle = proximity_model_bundles.find(item => item.id == id)
  if bundle != none {
    model-bundle-figure(bundle)
    model-example(bundle)
    v(0.55em)
  }
}

// Values have the full page width: labels never compete with a long ciphertext column.
#let flow-detail-table(fields) = {
  for field in fields {
    let value = field.at(1)
    if type(value) == bool {
      block(width: 100%, breakable: false, above: 3pt, below: 3pt)[
        #text(size: 9pt)[#field.at(0)] #h(1fr)
        #text(size: 9pt, weight: "bold", fill: if value { rgb("087f8c") } else { rgb("b45309") })[
          #if value { [Verified] } else { [Not Verified] }
        ]
      ]
      continue
    }
    let value-text = if value == true { "true" } else if value == false { "false" } else { str(value) }
    block(width: 100%, breakable: value-text.len() > 2000, above: 5pt, below: 8pt)[
      #block(sticky: true, below: 3pt)[#text(size: 9pt, weight: "bold", fill: rgb("334155"))[#field.at(0)]]
      #block(width: 100%, breakable: true, fill: rgb("f6f8fb"), inset: 9pt, radius: 3pt)[
        #set text(size: 8.5pt, font: "DejaVu Sans Mono")
        #autobreaking(raw(value-text, lang: "text"))
      ]
    ]
  }
}

#let step-diagram(graph-index, index) = block(sticky: true)[
  #proximity_flow_graph(steps: (proximity_flow.at(graph-index).steps.at(index),))
]

#let flow-message-details(step, flow-id) = {
  let payload = step.stages.find(stage => stage.stage == "payload")
  let encryption = step.stages.find(stage => stage.stage == "encryption")
  let cbor-encoding = step.stages.find(stage => stage.stage == "CBOR encoding")
  let cbor-decoding = step.stages.find(stage => stage.stage == "CBOR decoding")
  let decryption = step.stages.find(stage => stage.stage == "decryption")
  let json-decoding = step.stages.find(stage => stage.stage == "JSON decoding")
  let decoded = json-decoding.decoded_value
  let decoded-fields = if step.id.ends-with(".reader_request") {
    (
      ("Decoded JSON · requests[0].protocol", decoded.requests.at(0).protocol),
      ("Decoded JSON · requests[0].data.request", decoded.requests.at(0).data.request),
    )
  } else {
    (("Decoded JSON · vp_token[0]", decoded.vp_token.at(0)),)
  }
  [
    ===== Payload And Encryption
    / Check: Encode the JSON as UTF-8. Encrypt those exact bytes using the sender's session key and nonce.
    #proximity-code-sample(
      if step.id.ends-with(".reader_request") { "kotlin_reader_request_encryption" } else { "kotlin_wallet_submit_response" },
      instance: flow-id,
    )
    #flow-detail-table((
      ("Counter", encryption.counter),
      ("IV / nonce", encryption.iv_hex),
      ("Plaintext JSON", payload.utf8),
      ("Plaintext UTF-8 bytes", payload.utf8_hex),
      ("Ciphertext + 16-byte tag", encryption.ciphertext_and_tag_hex),
    ))

    ===== CBOR Envelope Encoding
    / Check: Place the ciphertext and its authentication tag in the envelope's `data` byte string; encode the CBOR map.
    #flow-detail-table((
      ("Model", cbor-encoding.model),
      ("Encoded envelope bytes", cbor-encoding.cbor_hex),
    ))

    ===== Envelope Decoding And Decryption
    / Check: Decode CBOR first, then authenticate and decrypt `data`. Decode the resulting UTF-8 JSON and compare it with the source payload.
    #proximity-code-sample(
      if step.id.ends-with(".reader_request") { "kotlin_wallet_request_decryption" } else { "rust_iso_aes_gcm_decrypt" },
      instance: flow-id,
    )
    #flow-detail-table((
      ("Envelope CBOR round-trip", cbor-encoding.CBOR_round_trip_verified),
      ("Decoded envelope data bytes", cbor-decoding.decoded_data_field_hex),
      ("Envelope data field matches ciphertext", cbor-decoding.decoded_data_matches_ciphertext),
      ("Decrypted UTF-8", decryption.output_utf8),
      ("Decrypted UTF-8 bytes", decryption.output_utf8_hex),
      ..decoded-fields,
      ("JSON matches the source payload", json-decoding.decoded_value_matches_original_payload),
    ))
  ]
}

#let flow-walkthrough(title, flow-id, graph-index) = [
  === #title

  #let flow-example = proximity_examples.find(example => example.id == flow-id)
  #let flow = json(bytes(flow-example.payload_json))
  #let trace-steps = flow.verification_trace.steps
  #let key-step = trace-steps.find(step => step.id == flow-id + ".session_transcript_and_keys")
  #let request-step = trace-steps.find(step => step.id == flow-id + ".reader_request")
  #let response-step = trace-steps.find(step => step.id == flow-id + ".wallet_response")
  #let engagement-example-id = if flow-id == "normal_flow" { "device_engagement" } else { "reader_engagement" }
  #let encryption-example-id = if flow-id == "normal_flow" { "encryption" } else { "encryption_reverse" }
  #let encryption-example = proximity_examples.find(example => example.id == encryption-example-id)
  #let encryption-sample = json(bytes(encryption-example.payload_json))

  #text(size: 8pt, fill: rgb("475569"))[
    Flow example: #ref(label("payload-" + flow-id)) · verified trace: #ref(label("trace-" + flow-id + ".engagement_qr"))
  ]
  #v(0.4em)
  #callout([How To Follow This Example], [
    Each phase pairs a sequence panel with the exact test values used at that point.
    Teal identifies the wallet; indigo identifies the reader. Returning arrows denote local work.
    Follow payload links for the complete JSON and trace links for the assertions.
  ])

  ==== Terms Used Below
  *QR text* is the `mdoc:` prefix plus Base64URL-encoded engagement CBOR. The session *envelope* is
  the `SessionEstablishment` or `SessionData` CBOR map. The 12-byte GCM nonce is the role-specific
  8-byte identifier followed by the 4-byte big-endian message counter. The key tables show the
  test-only derivation values once; the complete structured values are in the linked JSON payloads.

  ==== QR-Code Payload
  #step-diagram(graph-index, 0)
  / Action: Scan the engagement, remove the `mdoc:` prefix, Base64URL-decode, then parse CBOR.
  #proximity-code-sample("kotlin_engagement_qr_decode", instance: flow-id)
  #flow-detail-table((
    ("Engagement model", flow.qr_payload.model),
    ("QR text", flow.qr_payload.qr),
    ))
    See the encoded engagement in #ref(label("payload-" + engagement-example-id)).

  #if flow-id == "normal_flow" [
    ==== BLE Connection
    #step-diagram(graph-index, 1)
    / Action: Discover the advertised service, subscribe to State and Server2Client, then write `0x01` to State to signal readiness.
    #proximity-code-sample("kotlin_verifier_engagement_scan", instance: flow-id)
  ]

  #if flow-id == "reverse_flow" [
    ==== First BLE Application Message
    #step-diagram(graph-index, 1)
    / Action: Send the raw `DeviceEngagement` CBOR as the first logical application message. The reader needs its public key before deriving session keys.
    #proximity-code-sample("kotlin_send_device_engagement", instance: flow-id)
    #flow-detail-table((
      ("Model", flow.after_ble_connection.first_application_message_model),
      ("First-message CBOR bytes", flow.after_ble_connection.first_application_message_cbor_hex),
    ))
    `TransferMethods` (CBOR key `2`) is omitted from this reverse-flow message; the wallet already
    selected the transport advertised by `ReaderEngagement`. See the complete structured value in
    #ref(label("payload-reverse_device_engagement")).
    #proximity-code-sample("kotlin_doc_test_flow_variants")
  ]

  ==== Session Transcript
  #step-diagram(graph-index, 2)
  / Action: Construct the transcript from DeviceEngagement, EReaderKey, and the null handover. The reader can derive its keys first; the wallet can complete derivation once it receives EReaderKey.
  #proximity-code-sample("kotlin_session_transcript_ecdh", instance: flow-id)
  #flow-detail-table((
    ("Tag-24-wrapped transcript hex", flow.session_transcript_outer_hex),
    ("Origin", flow.origin),
  ))

  ==== Key Derivation
  ===== Private Keys
  #flow-detail-table((
    ("Key 1 · Reader private scalar (documentation only)", encryption-sample.documentation_only_reader_private_scalar_hex),
    ("Key 2 · Wallet private scalar (documentation only)", encryption-sample.documentation_only_device_private_scalar_hex),
    ("Reader public key (SEC1)", key-step.ecdh.reader_public_key_sec1_hex),
    ("Wallet public key (SEC1)", key-step.ecdh.device_public_key_sec1_hex),
  ))

  ==== Shared Secret
  / ECDH: Each actor combines its own private key with the other actor's public key. The matching result `Z_ab` becomes HKDF input key material; it is never sent over BLE.
  #proximity-code-sample("rust_iso_ecdh_key_material", instance: flow-id)
  #proximity-code-sample("rust_iso_hkdf", instance: flow-id)
  #flow-detail-table((
    ("Reader ECDH result", key-step.ecdh.reader_ecdh_shared_secret_hex),
    ("Wallet ECDH result", key-step.ecdh.device_ecdh_shared_secret_hex),
    ("ECDH key material / Z_ab (HKDF IKM)", key-step.ecdh.key_material_hex),
    ("Key material is used as HKDF input", key-step.ecdh.key_material_is_hkdf_ikm),
    ("Both peers derive the same secret", key-step.ecdh.both_peers_derive_same_secret),
    ("HKDF-SHA-256 parameters", key-step.key_derivation.algorithm),
    ("HKDF input key material", key-step.key_derivation.input_key_material_hex),
    ("SKReader", key-step.key_derivation.sk_reader_hex),
    ("SKDevice", key-step.key_derivation.sk_device_hex),
  ))

  ==== First Message
  #text(size: 8pt, fill: rgb("475569"))[SessionEstablishment from reader to wallet · #request-step.direction]
  #step-diagram(graph-index, 3)
  #flow-message-details(request-step, flow-id)

  ===== Reader Authentication And Consent
  #step-diagram(graph-index, 4)
  / Swiss Profile: The wallet checks verifier attestations, the expected origin, and `dc_api.jwt` before requesting consent.
  #callout([Fixture Boundary], [
    Transport encoding and encryption are verified. The placeholder attestation in this sample is
    not a valid Swiss trust chain; a production verifier-attestation check must succeed before consent.
  ])

  ==== Response
  #text(size: 8pt, fill: rgb("475569"))[SessionData from wallet to reader · #response-step.direction]
  #step-diagram(graph-index, 5)
  #flow-message-details(response-step, flow-id)
]

#let trace-card(step) = [
  #figure(
    block(
    width: 100%,
    breakable: true,
    fill: luma(97%),
    stroke: (paint: luma(82%), thickness: 0.45pt),
    radius: 0.35em,
    inset: 0.6em,
  )[
    #text(size: 8.5pt, weight: "bold", fill: rgb("0f172a"))[#step.name]
    #linebreak()
    #text(size: 8pt, fill: rgb("475569"))[#step.id]
    #h(0.4em) · #h(0.4em)
    #text(size: 8pt)[#ref(label("payload-" + step.example_ref))]
    #if step.source_refs.len() > 0 [
      #h(0.4em) · #h(0.4em)
      #text(size: 8pt)[Implementation:]
      #for source in step.source_refs [
        #h(0.2em)#ref(label(source))
      ]
    ]
    #v(0.35em)
    #set text(size: 8pt, font: "DejaVu Sans Mono")
    #autobreaking(raw(step.payload_display_json, lang: "json"))
    ],
    caption: [Verification trace #text(font: "DejaVu Sans Mono")[#step.id]],
    kind: "figure",
    supplement: [Trace],
  )
  #label("trace-" + step.id)
]

= ISO 18013-5 Proximity Implementation

The Kapun proximity module implements the ISO 18013-5 BLE transport for an mDL reader and an
mDL wallet. The wire examples below are generated from the Rust documentation generator and the
labelled Kotlin/JVM vectors. The generated payloads are documentation fixtures, not production
credentials or keys.

== Bluetooth Service Definition

The service and characteristic UUIDs are defined by the two transport implementations. Selecting
the central-client or peripheral-server variant is an implementation choice; it is not a fixed
ISO requirement and the engagement flags advertise the choice made for a particular session. The
examples below use wallet peripheral-server / reader central-client for the normal flow and the
corresponding reverse-engagement arrangement.

=== Choosing The BLE Roles

The choice balances a smooth start on the user's phone with predictable service discovery.
In these transport variants, the peripheral hosts the GATT server and advertises; the central
connects as the GATT client and discovers its services. QR direction is a separate choice:
reverse engagement changes who presents the QR without necessarily swapping these BLE roles.

#table(
  columns: (2.6cm, 1fr, 1fr),
  table.header([*Consideration*], [*Wallet Peripheral / Reader Central*], [*Wallet Central / Reader Peripheral*]),
  [User Experience],
  [Can benefit from Android configurations where BLE server operation remains available while the visible Bluetooth switch is off. This can avoid an unexpected settings step for users who normally disable Bluetooth.],
  [The wallet must be able to scan and connect. Bluetooth readiness and permissions should be checked before the user starts verification.],
  [Service Discovery],
  [The reader discovers the phone's exposed GATT database. More services, characteristics, and descriptors can mean more discovery work and a longer wait.],
  [The wallet discovers the reader's database. Managed reader infrastructure can keep the exposed services small and consistent.],
  [Operational Control],
  [Discovery latency depends on the user's phone, OS, registered services, and cache state. Measure on representative devices.],
  [Reader owners can tune and test the server configuration. This is attractive when predictable discovery time matters most.],
)

/ Android Behaviour: AOSP distinguishes an LE-only state from the fully off state, and documents
  GATT client/server use in that LE-only mode. Availability depends on platform, permissions,
  and configuration; a disabled switch does not by itself establish that advertising will work.
  Kapun's current `GattServer.startAdvertising` requires an enabled adapter. The potential benefit
  above therefore needs validation on the intended devices and advertising path.

/ Discovery Cost: Android's `discoverServices()` discovers services together with their
  characteristics and descriptors. A larger exposed database can increase discovery work;
  the actual delay also depends on caching and the link. Choosing the inverse arrangement can
  be sensible when the reader operator controls that database more closely.

#text(size: 8pt, fill: rgb("64748b"))[
  Platform references:
  #link("https://android.googlesource.com/platform/frameworks/base/+/9c3627ab872738258dfbdeeba6e5a7b51dd3a340/core/java/android/bluetooth/BluetoothAdapter.java")[AOSP LE-Only State] ·
  #link("https://developer.android.com/reference/android/bluetooth/BluetoothGatt#discoverServices()")[Android Service Discovery].
]

=== Service Characteristics

#figure(caption: [Wallet / peripheral-server characteristics])[
  #table(
    columns: (1fr, 1fr, 1fr),
    stroke: 1pt,
    row-gutter: 0em,
    table.header([*Characteristic*], [*UUID*], [*Properties*]),
    [State], [`00000001-A123-48CE-896B-4C76973373E6`], [`PROPERTY_NOTIFY`, `PROPERTY_WRITE_NO_RESPONSE`],
    [Client2Server], [`00000002-A123-48CE-896B-4C76973373E6`], [`PROPERTY_WRITE_NO_RESPONSE`],
    [Server2Client], [`00000003-A123-48CE-896B-4C76973373E6`], [`PROPERTY_NOTIFY`],
  )
]

#figure(caption: [Reader / central-client characteristics])[
  #table(
    columns: (1fr, 1fr, 1fr),
    stroke: 1pt,
    row-gutter: 0em,
    table.header([*Characteristic*], [*UUID*], [*Properties*]),
    [State], [`00000005-A123-48CE-896B-4C76973373E6`], [`PROPERTY_NOTIFY`, `PROPERTY_WRITE_NO_RESPONSE`],
    [Client2Server], [`00000006-A123-48CE-896B-4C76973373E6`], [`PROPERTY_WRITE_NO_RESPONSE`],
    [Server2Client], [`00000007-A123-48CE-896B-4C76973373E6`], [`PROPERTY_NOTIFY`],
    [Ident], [`00000008-A123-48CE-896B-4C76973373E6`], [`PROPERTY_READ`],
  )
]

== Connection And Message Framing

The BLE peripheral advertises the UUID from `DeviceEngagement`. After connection, the GATT client
subscribes to `State` and `Server2Client`, then signals readiness by writing `0x01` to `State`.
Application messages are fragmented to three bytes less than the MTU. Each fragment starts with
`0x01` when more fragments follow and `0x00` for the last fragment.

The first *logical* application message differs by engagement variant:

- normal flow: the reader scans `DeviceEngagement`, derives the session cipher after connection,
  and sends `SessionEstablishment`;
- reverse flow: the wallet scans `ReaderEngagement`, connects, and sends the raw `DeviceEngagement`
  without a `TransferMethods` map (CBOR key `2`) as its first logical application message. The reader
  parses it, derives the cipher, and then sends `SessionEstablishment`.

The exact payloads are linked by the stable IDs `normal_flow` and `reverse_flow` in the generated
JSON appendix.

The snippets below sit beside the corresponding transport branches: normal engagement scans the
wallet's `DeviceEngagement`; reverse engagement sends that engagement as the wallet's first BLE
application message.

#proximity-code-sample("kotlin_verifier_engagement_scan")
#proximity-code-sample("kotlin_send_device_engagement")
#proximity-code-sample("kotlin_verifier_reverse_and_response")

== Reader Engagement

In reverse engagement, the reader (Check-App) presents a QR code containing `ReaderEngagement`.
The generated fixture advertises central-client mode for the reader and peripheral-server mode for
the wallet: CBOR key `0` is `false` / `true`, respectively, and key `1` is `true` / `false`,
respectively. These complementary flags describe this implementation choice; another deployment
can select the inverse transport arrangement when its platform and GATT service database make that
more suitable.

#proximity-code-sample("kotlin_engagement_qr_decode")

#figure(caption: [ReaderEngagement model])[
#diag-notation(```diag-notation
ReaderEngagement = {
  0: tstr, ; SDK version, currently "1.1"
  1: Security,
  ? 2: TransferMethods,
  ? 6: Capabilities
}
Security = [
  uint, ; cipher suite identifier, 1 for ECDH
  #6.24(bstr .cbor COSE_Key), ; EReaderKey public key
]
TransferMethods = [* TransferMethod]
TransferMethod = [uint, uint, BleOptions]
BleOptions = {
  ? 0: bool, ; peripheral server mode
  ? 1: bool, ; central client mode
  ? 10: bstr, ; peripheral-server UUID
  ? 11: bstr, ; central-client UUID
}
Capabilities = {* int => any}
```)
]

#include-model-bundle("reader_engagement")

== Device Engagement

In normal engagement, the wallet advertises `DeviceEngagement` and the reader scans it. This QR
payload includes `TransferMethods` (CBOR key `2`) so the reader can select a transport. In reverse
engagement, the wallet scans `ReaderEngagement`, connects using its advertised transport, then
sends a `DeviceEngagement` as the first application message. The reverse-flow builder passes null
central-client and peripheral-server UUIDs, so it omits `TransferMethods` entirely; the transport
was already selected from the reader's engagement. Version `1.1`, `Security`, and `Capabilities`
remain in that CBOR map. The SDK emits version `1.1`.

#proximity-code-sample("kotlin_reverse_engagement_builder")

The generated Rust vector uses P-256 COSE keys so the ECDH and key derivation are reproducible.
The public key is carried inside tag 24 as a CBOR-encoded COSE key with `kty = 2`, `crv = 1`, and
the `x` and `y` coordinates at `-2` and `-3`. The public SDK factory defaults remain configurable
and currently default to X25519 unless `KeyType.P256` is selected.

=== COSE_Key Parameter Overview

The proximity `MdlCoseKey` encoder uses the following public-key layouts. The labels in the
`Kapun KeyType` column refer to the SDK enum; all private `d` values stay local and are never part
of an engagement.

#figure(
  block(width: 100%, breakable: true)[
    #set text(size: 8pt)
    #table(
      columns: (2.8cm, 0.85cm, 0.85cm, 5.0cm, 1fr),
      gutter: 0.2em,
      stroke: (paint: luma(86%), thickness: 0.35pt),
      align: left + horizon,
      table.header([*Key / Use*], [*kty*], [*crv*], [*Public Parameters*], [*Kapun Mapping*]),
      [P-256 / EC2 / ECDH],
      [2],
      [1],
      [#text(font: "DejaVu Sans Mono")[−2: x, −3: y]; `x` and `y` are 32-byte bstr values; uncompressed SEC1 public key is 65 bytes],
      [#text(font: "DejaVu Sans Mono")[KeyType.P256]; used for the generated ECDH vectors],
      [X25519 / OKP / ECDH],
      [1],
      [4],
      [#text(font: "DejaVu Sans Mono")[−2: x]; 32-byte bstr; no `y` coordinate],
      [#text(font: "DejaVu Sans Mono")[KeyType.X25519]; Kapun's X25519 DH key type],
      [Ed25519 / OKP / EdDSA],
      [1],
      [6],
      [#text(font: "DejaVu Sans Mono")[−2: x]; 32-byte bstr; no `y` coordinate],
      [COSE signing key layout; not used by Kapun's proximity DH encoder],
    )
  ],
  kind: "figure",
  supplement: [Table],
  caption: [COSE_Key public parameters for Kapun proximity and EdDSA signing],
)

The distinction between X25519 and Ed25519 is important: COSE `crv = 4` is X25519 for ECDH,
whereas `crv = 6` is Ed25519 for EdDSA signatures. The current Kapun proximity encoder emits
`crv = 4` for `KeyType.X25519`; it does not use an Ed25519 signing key for the proximity ECDH
exchange. See #link("https://www.rfc-editor.org/rfc/rfc9053.html")[RFC 9053] for the COSE key
parameters and curve assignments.

For the public keys emitted by `MdlCoseKey`, COSE label `1` (`kty`), label `-1` (`crv`), and
label `-2` (`x`) are always present. Label `-3` (`y`) is present only for EC2/P-256. The encoder
does not add `alg` (`3`), `key_ops` (`4`), `kid` (`2`), or private key material `d` (`-4`).

#proximity-code-sample("kotlin_engagement_encode")

#figure(caption: [DeviceEngagement model])[
#diag-notation(```diag-notation
DeviceEngagement = {
  0: tstr,
  1: Security,
  ? 2: TransferMethods,
  ? 6: Capabilities,
  * int => any
}
Security = [uint, #6.24(bstr .cbor COSE_Key)]
Capabilities = { ? 0x44437631 => [tstr], * int => any }
```)
]

#include-model-bundle("device_engagement")

These two model codecs show the Kotlin field names and string-keyed CBOR maps used on the wire.

#proximity-code-sample("kotlin_session_establishment_cbor")
#proximity-code-sample("kotlin_session_data_cbor")

== Session Establishment, Encryption, And Response

When `dcApiSelected` is true, the SDK wraps the complete PAR JWT in the JSON DC API envelope and
uses protocol `openid4vp-v1-signed`. It currently forwards the JWT rather than reconstructing the
presentation request from claims. `SessionEstablishment.data` contains the AES-GCM ciphertext.

#diag-notation(```diag-notation
SessionEstablishment = {
  "eReaderKey": #6.24(bstr .cbor COSE_Key),
  "data": bstr, ; encrypted DC API request
  ? "dcApiSelected": bool
}

SessionData = {
  ? "data": bstr, ; encrypted response
  ? "status": uint,
  ? "shaSum": bstr, ; Swiss/debug extension
  ? "dcApiSelected": bool
}
```)

#include-model-bundle("session_establishment")
#include-model-bundle("session_data")
#include-model-bundle("dc_api_request")

The generic model does not require `shaSum`; the current proximity code validates it when present.
The generated examples retain it only as the existing Swiss/debug extension.

The highlighted lines connect the request/response payloads to the implementation's encryption,
envelope handling, and decryption operations. The test excerpts show the byte-for-byte assertions
that back the documentation vectors.

#proximity-code-sample("kotlin_reader_request_encryption")
#proximity-code-sample("rust_iso_aes_gcm_encrypt")
#proximity-code-sample("kotlin_wallet_request_decryption")
#proximity-code-sample("kotlin_wallet_submit_response")
#proximity-code-sample("rust_iso_aes_gcm_decrypt")
#proximity-code-sample("kotlin_doc_test_round_trip")
#proximity-code-sample("kotlin_doc_test_flow_round_trip")

#include "session_encryption.typ"

== Session Transcript And Origin

Both variants derive the same transcript shape once the wallet `DeviceEngagement` is known:

#diag-notation(```diag-notation
SessionTranscript = [
  #6.24(bstr .cbor DeviceEngagement),
  #6.24(bstr .cbor EReaderKey),
  null,
]
```)

#include-model-bundle("session_transcript")
#include-model-bundle("ecdh_key_material")

The SDK hashes the CBOR encoding of that transcript and constructs
`iso-18013-5://<base64url(sha256(transcript-cbor))>`. That origin is passed into the OpenID4VP
document request and is also available in the generated encryption examples.

#proximity-code-sample("kotlin_session_transcript_ecdh")
#proximity-code-sample("rust_iso_ecdh_key_material")
#proximity-code-sample("kotlin_session_transcript_origin")
#proximity-code-sample("rust_iso_hkdf")

== Reader Authentication In The Swiss Profile

The proximity transport decrypts and forwards the signed OpenID4VP request. Swiss-profile reader
authentication is a profile-layer decision: the wallet must validate the verifier attestations and
associated verifier information according to the Swiss OID4VP profile, then validate the expected
origin and the required `response_mode` (`dc_api.jwt`) before showing consent.

The presentation request model already carries `verifier_attestations`, `verifier_info`, and
`expected_origins`. The generic proximity transport does not itself establish Swiss trust; the
Swiss presentation/trust integration must consume those fields. This boundary is represented in
the generated end-to-end payload and is intentionally not replaced by a generic transport check.

#include-model-bundle("swiss_verifier_inputs")

#pagebreak()
== Detailed Normal And Reverse Flow Walkthroughs

These walkthroughs are the primary worked examples. Each follows its engagement from the QR
payload through transcript and key derivation, then traces the request and response through
envelope encoding, decoding, decryption, and JSON decoding. Payload and trace references link to
the figures later in the appendices; exact unabbreviated values are also emitted in the JSON
sidecars.

#flow-walkthrough("Normal Flow", "normal_flow", 1)

#pagebreak()
#flow-walkthrough("Reverse Flow", "reverse_flow", 0)

#pagebreak()
== Model Reference

The complete generated model-bundle listing is kept here for reference. In the protocol sections
above, the relevant bundle is repeated next to the first discussion of that flow so the model
cards and their example elements are available in context. Every bundle recursively resolves its
dependent models down to primitive CBOR or JSON wire types.

The structured values remain available to other Typst documents as `proximity_models`,
`proximity_model_bundles`, and `proximity_models_json`.

#for bundle in proximity_model_bundles {
  model-bundle-figure(bundle)
  model-example(bundle)
  v(0.55em)
}

#pagebreak()
== Step-By-Step Verification Traces

Each trace item records the semantic payload, encoded bytes, encryption/decryption evidence, and
the decoded value where applicable. The Rust generator executes these checks for both variants.
Payload references resolve to sample figures; code references link to the focused source samples
shown inline in the protocol sections. Swiss verifier-attestation signature validation is deliberately marked unverified:
the fixture contains a placeholder JWS, not a valid Swiss attestation and trust chain.

#for flow in proximity_examples.filter(example => example.verification_steps.len() > 0) [
== #flow.name
  #for step in flow.verification_steps [
    #trace-card(step)
    #v(0.5em)
  ]
]

== End-To-End Flow Index

The stable top-level flow IDs are `normal_flow` and `reverse_flow`. Their full step payloads are
available as exact JSON in `proximity-flow.json`; abbreviated print-safe JSON is shown in the
example and trace figures below.

#block[
  #set text(size: 8pt, font: "DejaVu Sans Mono")
  #autobreaking(raw(proximity_flow_json, lang: "json"))
]

#pagebreak()
== Machine-Readable Example Payloads

Each card below is a print-safe, parseable JSON view with a stable `id`. Long byte strings are
abbreviated with their length, prefix, and suffix so the cards remain readable; the exact payloads
are emitted beside the document as `proximity-examples.json` and `proximity-flow.json`. The flow
graphs and flow trace refer to these IDs using `example_ref` and `example_refs`, so a reader can
jump from a graph node to the exact payload. With `--include-kotlin-examples`, the appendix also
contains `kotlin_*` records produced by the labelled Kotlin/JVM tests.

#for example in proximity_examples {
  json-card(example)
  v(0.7em)
}
