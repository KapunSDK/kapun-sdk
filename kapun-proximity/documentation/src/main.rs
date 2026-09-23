//! Generate the data and narrative Typst sources for the proximity appendix.
//!
//! The data source is the includeable artifact:
//!
//!     cargo run -p kapun-proximity-docgen -- --output-dir ./generated
//!
//! `--validate` feeds the combined data and narrative sources through the same Typst world used
//! by the PDF renderer. It does not write a PDF.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use kapun_crypto_rust::iso180135::{
    Role, decrypt_epoch_iso_180135, encrypt_epoch_iso_180135, hkdf_iso_180135,
};
use p256::{SecretKey, ecdh::diffie_hellman};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Model {
    id: &'static str,
    name: &'static str,
    encoding: &'static str,
    dependencies: Vec<&'static str>,
    example_ref: &'static str,
    kotlin_example_ref: &'static str,
    fields: Vec<Field>,
}

#[derive(Serialize)]
struct ModelBundle {
    id: &'static str,
    title: &'static str,
    model_ids: Vec<&'static str>,
    example_ref: &'static str,
    kotlin_example_ref: &'static str,
}

#[derive(Serialize)]
struct Field {
    name: &'static str,
    cbor_key: JsonValue,
    wire_type: &'static str,
    optional: bool,
    description: &'static str,
}

struct Example {
    id: &'static str,
    name: &'static str,
    payload: JsonValue,
}

enum ExampleRecord {
    Rust(Example),
    Kotlin {
        id: String,
        name: String,
        payload: JsonValue,
    },
}

impl ExampleRecord {
    fn id(&self) -> &str {
        match self {
            Self::Rust(example) => example.id,
            Self::Kotlin { id, .. } => id,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Rust(example) => example.name,
            Self::Kotlin { name, .. } => name,
        }
    }

    fn payload(&self) -> &JsonValue {
        match self {
            Self::Rust(example) => &example.payload,
            Self::Kotlin { payload, .. } => payload,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    eprintln!("[docgen] preparing Rust proximity vectors");
    let models = models();
    let model_bundles = model_bundles(&models);
    let code_source = generate_code_source(&repository_root());
    let mut examples = examples()
        .into_iter()
        .map(ExampleRecord::Rust)
        .collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--include-kotlin-examples") {
        examples.extend(run_kotlin_examples());
    }
    eprintln!("[docgen] generating Typst data, graph, and narrative sources");
    let data_source = generate_data_source(&models, &model_bundles, &examples);
    let graph_source = generate_graph_source();
    let text_source = generate_text_source();
    let document_source = generate_document_source();

    if args.iter().any(|arg| arg == "--validate") {
        eprintln!("[docgen] validating the combined document with the Kapun Typst renderer");
        validate_typst_document(
            &document_source,
            &data_source,
            &graph_source,
            &text_source,
            &code_source,
        );
        eprintln!("[docgen] Typst validation passed");
    }

    if let Some(output_dir) = option_value(&args, "--output-dir") {
        eprintln!("[docgen] writing generated sources and exact JSON sidecars to {output_dir}");
        fs::create_dir_all(&output_dir).expect("documentation output directory is writable");
        write_source(
            Path::new(&output_dir).join("proximity-data.typ"),
            &data_source,
        );
        write_source(
            Path::new(&output_dir).join("proximity-flow-graph.typ"),
            &graph_source,
        );
        write_source(
            Path::new(&output_dir).join("proximity-code.typ"),
            &code_source,
        );
        write_source(
            Path::new(&output_dir).join("session_encryption.typ"),
            include_str!("../session_encryption.typ"),
        );
        write_source(
            Path::new(&output_dir).join("diag-notation.typ"),
            include_str!("../diag-notation.typ"),
        );
        write_source(
            Path::new(&output_dir).join("diag-notation.sublime-syntax"),
            include_str!("../diag-notation.sublime-syntax"),
        );
        write_source(
            Path::new(&output_dir).join("proximity-text.typ"),
            &text_source,
        );
        write_source(
            Path::new(&output_dir).join("proximity.typ"),
            &document_source,
        );
        write_source(
            Path::new(&output_dir).join("proximity-models.json"),
            &serde_json::to_string_pretty(&json!({
                "models": models,
                "bundles": model_bundles,
            }))
            .expect("model JSON is serializable"),
        );
        write_source(
            Path::new(&output_dir).join("proximity-examples.json"),
            &examples_json(&examples),
        );
        write_source(
            Path::new(&output_dir).join("proximity-flow.json"),
            &flow_json(&examples),
        );
        return;
    }

    let mut wrote_file = false;
    if let Some(path) = option_value(&args, "--data-output") {
        write_source(Path::new(&path), &data_source);
        wrote_file = true;
    }
    if let Some(path) = option_value(&args, "--text-output") {
        write_source(Path::new(&path), &text_source);
        wrote_file = true;
    }

    // With no output path, print the includeable data document. This keeps the command useful in
    // pipes while `--output-dir` provides the two named documents for normal builds.
    if !wrote_file {
        print!("{data_source}");
    }
}

fn option_value(args: &[String], option: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == option)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct CodeExcerpt<'a> {
    id: &'a str,
    title: &'a str,
    language: &'a str,
    source_path: &'a str,
    needle: &'a str,
    focus: &'a str,
}

fn code_excerpts() -> Vec<CodeExcerpt<'static>> {
    vec![
        CodeExcerpt {
            id: "kotlin_engagement_qr_decode",
            title: "Kotlin: QR and CBOR engagement decoding",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/protocol/mdl/MdlEngagement.kt",
            needle: "fun fromQrCode",
            focus: "base64UrlDecode(encodedData)",
        },
        CodeExcerpt {
            id: "kotlin_engagement_encode",
            title: "Kotlin: BLE flags in DeviceEngagement CBOR",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/protocol/mdl/MdlEngagementBuilder.kt",
            needle: "fun getEngagementBytes",
            focus: "bleTransportOptions.put(0, peripheralServerModeSupported)",
        },
        CodeExcerpt {
            id: "kotlin_session_establishment_cbor",
            title: "Kotlin: SessionEstablishment CBOR map encoding",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/protocol/mdl/MdlSessionEstablishment.kt",
            needle: "fun asCbor()",
            focus: "return encodeCbor(mapOf(",
        },
        CodeExcerpt {
            id: "kotlin_session_data_cbor",
            title: "Kotlin: SessionData CBOR map encoding",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/protocol/mdl/MdlSessionData.kt",
            needle: "fun asCbor",
            focus: "return encodeCbor(mapOf(",
        },
        CodeExcerpt {
            id: "kotlin_session_transcript_ecdh",
            title: "Kotlin: SessionTranscript and ECDH session cipher setup",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/protocol/mdl/MdlCentralClientModeTransportProtocol.kt",
            needle: "override fun getSessionCipher",
            focus: "sessionTranscript = listOf",
        },
        CodeExcerpt {
            id: "kotlin_reader_request_encryption",
            title: "Kotlin: encode, encrypt, and send SessionEstablishment",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/verifier/ProximityVerifier.kt",
            needle: "fun requestDocument",
            focus: "val encryptedData = currentCipher.encrypt",
        },
        CodeExcerpt {
            id: "kotlin_verifier_engagement_scan",
            title: "Kotlin: verifier scans DeviceEngagement and selects the transport",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/verifier/ProximityVerifier.kt",
            needle: "fun <T> create(",
            focus: "val deviceEngagement = MdlEngagement.fromQrCode(engagementData)",
        },
        CodeExcerpt {
            id: "kotlin_send_device_engagement",
            title: "Kotlin: wallet sends DeviceEngagement on the reverse-flow transport",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/wallet/ProximityWallet.kt",
            needle: "fun sendDeviceEngagement",
            focus: "transportProtocol.sendMessage(engagementData)",
        },
        CodeExcerpt {
            id: "kotlin_reverse_engagement_builder",
            title: "Kotlin: reverse wallet builds DeviceEngagement without transfer methods",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/wallet/ProximityWallet.kt",
            needle: "fun createReverse(",
            focus: "false,",
        },
        CodeExcerpt {
            id: "kotlin_wallet_request_decryption",
            title: "Kotlin: decode, decrypt, and parse SessionEstablishment",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/wallet/ProximityWallet.kt",
            needle: "private fun processMessageReceived",
            focus: "sessionCipher?.decrypt(sessionEstablishment.data)",
        },
        CodeExcerpt {
            id: "kotlin_verifier_reverse_and_response",
            title: "Kotlin: verifier handles first reverse-flow message and SessionData",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/verifier/ProximityVerifier.kt",
            needle: "private fun processMessageReceived",
            focus: "MdlEngagement.fromCbor(message)",
        },
        CodeExcerpt {
            id: "kotlin_wallet_submit_response",
            title: "Kotlin: wallet encrypts and sends its response",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/wallet/ProximityWallet.kt",
            needle: "fun submitDocument",
            focus: "sessionCipher!!.encrypt(data)",
        },
        CodeExcerpt {
            id: "kotlin_session_transcript_origin",
            title: "Kotlin: transcript-derived ISO origin",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonMain/kotlin/org/kapunsdk/proximity/util/ProximityMdlUtils.kt",
            needle: "fun buildIsoOriginFromSessionTranscript",
            focus: "return \"iso-18013-5://${sessionTranscriptBytesHash}\"",
        },
        CodeExcerpt {
            id: "rust_iso_ecdh_key_material",
            title: "Rust: ECDH key material passed to HKDF",
            language: "rust",
            source_path: "kapun-crypto/rust/src/iso180135/mod.rs",
            needle: "pub fn get_session_cipher",
            focus: "let shared_secret = k.diffie_hellman(peer_public_key)?;",
        },
        CodeExcerpt {
            id: "rust_iso_hkdf",
            title: "Rust: role-separated HKDF-SHA-256 key derivation",
            language: "rust",
            source_path: "kapun-crypto/rust/src/iso180135/mod.rs",
            needle: "pub fn hkdf_iso_180135",
            focus: "let _ = hkdf.expand(",
        },
        CodeExcerpt {
            id: "rust_iso_aes_gcm_encrypt",
            title: "Rust: AES-256-GCM encryption and nonce construction",
            language: "rust",
            source_path: "kapun-crypto/rust/src/iso180135/mod.rs",
            needle: "pub fn encrypt_epoch_iso_180135",
            focus: "nonce[..8].copy_from_slice(match role {",
        },
        CodeExcerpt {
            id: "rust_iso_aes_gcm_decrypt",
            title: "Rust: AES-256-GCM decryption",
            language: "rust",
            source_path: "kapun-crypto/rust/src/iso180135/mod.rs",
            needle: "pub fn decrypt_epoch_iso_180135",
            focus: "Some(cipher.decrypt(nonce, ciphertext).ok()?)",
        },
        CodeExcerpt {
            id: "kotlin_doc_test_round_trip",
            title: "Kotlin/JVM documentation test: request and response round-trip",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonTest/kotlin/org/kapunsdk/proximity/protocol/mdl/ProximityDocumentationVectorTest.kt",
            needle: "fun documentation_encoded_request_response_and_encryption_round_trip",
            focus: "val encodedRequest = establishment.asCbor()",
        },
        CodeExcerpt {
            id: "kotlin_doc_test_flow_variants",
            title: "Kotlin/JVM documentation test: normal and reverse first messages",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonTest/kotlin/org/kapunsdk/proximity/protocol/mdl/ProximityDocumentationVectorTest.kt",
            needle: "fun documentation_normal_and_reverse_flow_first_application_messages",
            focus: "println(\"PROXIMITY_DOC[Reverse Flow].first_application_message_model=DeviceEngagement\")",
        },
        CodeExcerpt {
            id: "kotlin_doc_test_flow_round_trip",
            title: "Kotlin/JVM documentation test: complete session round-trip helper",
            language: "kotlin",
            source_path: "kapun-proximity/src/commonTest/kotlin/org/kapunsdk/proximity/protocol/mdl/ProximityDocumentationVectorTest.kt",
            needle: "private fun assertFlowRoundTrip",
            focus: "assertContentEquals(responsePlaintext, assertNotNull(readerCipher.decrypt(decodedResponseBytes)))",
        },
    ]
}

fn generate_code_source(repository_root: &Path) -> String {
    let excerpts = code_excerpts();
    let mut source = String::from(
        "// Generated focused source excerpts. Values are consumed inline by proximity-text.typ.\n\
         #import \"@preview/codly:1.3.0\": *\n\
         #let proximity_code_samples = (\n",
    );
    let mut source_cache = BTreeMap::<&str, String>::new();
    for excerpt in excerpts {
        if !source_cache.contains_key(excerpt.source_path) {
            let path = repository_root.join(excerpt.source_path);
            source_cache.insert(
                excerpt.source_path,
                fs::read_to_string(&path).unwrap_or_else(|error| {
                    panic!(
                        "could not read reference source {}: {error}",
                        path.display()
                    )
                }),
            );
        }
        let source_text = source_cache
            .get(excerpt.source_path)
            .expect("source text was loaded");
        let display_source = strip_todo_comments(source_text);
        let context_lines = if excerpt.id == "kotlin_reverse_engagement_builder" {
            5
        } else {
            4
        };
        let (code, start_line, end_line, focus_line) = extract_focused_excerpt(
            &display_source,
            excerpt.needle,
            excerpt.focus,
            context_lines,
        )
        .unwrap_or_else(|| {
            panic!(
                "could not extract focus `{}` from code marker `{}`",
                excerpt.focus, excerpt.needle
            )
        });
        source.push_str(&format!(
            "  (id: {}, title: {}, language: {}, source: {}, start_line: {}, end_line: {}, focus_line: {}, code: {}),\n",
            typst_string(excerpt.id),
            typst_string(excerpt.title),
            typst_string(excerpt.language),
            typst_string(excerpt.source_path),
            start_line,
            end_line,
            focus_line,
            typst_string(&code),
        ));
    }
    source.push_str(
        ")\n\n#let proximity-code-sample(id, instance: none) = {\n\
           let sample = proximity_code_samples.find(item => item.id == id)\n\
           assert(sample != none, message: \"missing inline source excerpt: \" + id)\n\
           [\n\
             #figure(\n\
               block(width: 100%, breakable: true, fill: luma(98%), stroke: (paint: luma(84%), thickness: 0.4pt), radius: 0.3em, inset: 0.45em)[\n\
               #set align(left)\n\
               #set text(size: 8.5pt)\n\
               #text(size: 9pt, weight: \"bold\", fill: rgb(\"#1e293b\"))[#sample.title]\n\
               #linebreak()\n\
               #v(0.25em)\n\
               #codly(\n\
                 offset: sample.start_line - 1,\n\
                 highlighted-lines: (sample.focus_line,),\n\
                 highlighted-default-color: rgb(\"#fef3c7\"),\n\
               )\n\
               #raw(sample.code, lang: sample.language, block: true)\n\
               ],\n\
               kind: \"code\",\n\
               supplement: [Code],\n\
               caption: [#sample.source.split(\"/\").join(\"/\" + sym.zws):#sample.start_line–#sample.end_line · highlighted line #sample.focus_line],\n\
             )\n\
             #label(if instance == none { sample.id } else { sample.id + \"-\" + instance })\n\
           ]\n\
         }\n",
    );
    source
}

// Blank TODO comments for display only. Preserve every newline so Codly offsets still
// point at the original source. Strings and executable TODO(...) calls remain intact.
fn strip_todo_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        // Rust raw strings (r#"..."#) and Kotlin triple strings may contain comment markers.
        if bytes[i] == b'r' {
            let mut quote = i + 1;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let end = format!("\"{}", "#".repeat(quote - i - 1));
                i = source[quote + 1..]
                    .find(&end)
                    .map_or(bytes.len(), |n| quote + 1 + n + end.len());
                continue;
            }
        }
        if source[i..].starts_with("\"\"\"") {
            i = source[i + 3..]
                .find("\"\"\"")
                .map_or(bytes.len(), |n| i + 3 + n + 3);
            continue;
        }
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        let start = i;
        if bytes.get(i..i + 2) == Some(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes.get(i..i + 2) == Some(b"/*") {
            i += 2;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if bytes.get(i..i + 2) == Some(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes.get(i..i + 2) == Some(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else {
            i += source[i..]
                .chars()
                .next()
                .expect("character exists")
                .len_utf8();
            continue;
        }
        if source[start..i].to_ascii_uppercase().contains("TODO") {
            for byte in &mut output[start..i] {
                if *byte != b'\n' && *byte != b'\r' {
                    *byte = b' ';
                }
            }
        }
    }
    String::from_utf8(output).expect("only complete comments were replaced")
}

fn extract_focused_excerpt(
    source: &str,
    needle: &str,
    focus: &str,
    context_lines: usize,
) -> Option<(String, usize, usize, usize)> {
    let mut search_from = 0;
    while let Some(relative) = source.get(search_from..)?.find(needle) {
        let marker = search_from + relative;
        if let Some((item, item_start, _)) = extract_braced_item_at(source, marker) {
            let lines = item.lines().collect::<Vec<_>>();
            if let Some(focus_index) = lines.iter().position(|line| line.contains(focus)) {
                let start_index = focus_index.saturating_sub(context_lines);
                let end_index = (focus_index + context_lines + 1).min(lines.len());
                let selected = &lines[start_index..end_index];
                let common_indent = selected
                    .iter()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| line.len() - line.trim_start().len())
                    .min()
                    .unwrap_or(0);
                let code = selected
                    .iter()
                    .map(|line| {
                        line.get(common_indent..)
                            .unwrap_or(line)
                            .trim_end()
                            .replace('\t', "    ")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let start_line = item_start + start_index;
                let end_line = item_start + end_index - 1;
                let focus_line = item_start + focus_index;
                return Some((code, start_line, end_line, focus_line));
            }
        }
        search_from = marker + needle.len();
    }
    None
}

fn extract_braced_item_at(source: &str, marker: usize) -> Option<(String, usize, usize)> {
    let line_start = source[..marker].rfind('\n').map_or(0, |index| index + 1);
    let open = source[marker..].find('{')? + marker;
    let bytes = source.as_bytes();
    let mut index = open;
    let mut depth = 0usize;
    let mut state = 0u8; // 0 code, 1 string, 2 line comment, 3 block comment, 4 char literal
    let mut block_depth = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            0 => match (byte, next) {
                (b'/', Some(b'/')) => {
                    state = 2;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    state = 3;
                    block_depth = 1;
                    index += 1;
                }
                (b'"', _) => state = 1,
                (b'\'', _) => state = 4,
                (b'{', _) => depth += 1,
                (b'}', _) => {
                    depth -= 1;
                    if depth == 0 {
                        let end = index + 1;
                        let start_line =
                            source[..line_start].bytes().filter(|b| *b == b'\n').count() + 1;
                        let end_line = source[..end].bytes().filter(|b| *b == b'\n').count() + 1;
                        return Some((
                            source[line_start..end].trim_end().to_owned(),
                            start_line,
                            end_line,
                        ));
                    }
                }
                _ => {}
            },
            1 => {
                if byte == b'\\' {
                    index += 1;
                } else if byte == b'"' {
                    state = 0;
                }
            }
            2 => {
                if byte == b'\n' {
                    state = 0;
                }
            }
            3 => match (byte, next) {
                (b'/', Some(b'*')) => {
                    block_depth += 1;
                    index += 1;
                }
                (b'*', Some(b'/')) => {
                    block_depth -= 1;
                    index += 1;
                    if block_depth == 0 {
                        state = 0;
                    }
                }
                _ => {}
            },
            4 => {
                if byte == b'\\' {
                    index += 1;
                } else if byte == b'\'' {
                    state = 0;
                }
            }
            _ => unreachable!(),
        }
        index += 1;
    }
    None
}

fn write_source(path: impl AsRef<Path>, source: &str) {
    fs::write(path, source).expect("generated Typst source is writable");
}

fn run_kotlin_examples() -> Vec<ExampleRecord> {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let gradle_wrapper = repository_root.join("gradlew");
    eprintln!(
        "[docgen] running labelled Kotlin vectors via {} (Gradle output follows on stdout)",
        gradle_wrapper.display()
    );
    let mut child = Command::new(&gradle_wrapper)
        .args([
            ":kapun-proximity:jvmTest",
            "--tests",
            "*ProximityDocumentationVectorTest*",
            "--no-daemon",
            "--console=plain",
        ])
        .current_dir(&repository_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| {
            panic!(
                "could not run Kotlin documentation vectors with {}: {error}",
                gradle_wrapper.display()
            )
        });

    let log = Arc::new(Mutex::new(String::new()));
    let stdout = child
        .stdout
        .take()
        .expect("Gradle stdout is piped for documentation progress");
    let stderr = child
        .stderr
        .take()
        .expect("Gradle stderr is piped for documentation progress");
    let stdout_log = Arc::clone(&log);
    let stderr_log = Arc::clone(&log);
    let stdout_thread = thread::spawn(move || stream_child_output(stdout, stdout_log));
    let stderr_thread = thread::spawn(move || stream_child_output(stderr, stderr_log));
    let status = child
        .wait()
        .expect("Gradle documentation vector process can be waited on");
    stdout_thread
        .join()
        .expect("Gradle stdout forwarding thread did not panic");
    stderr_thread
        .join()
        .expect("Gradle stderr forwarding thread did not panic");
    let log = Arc::try_unwrap(log)
        .expect("Gradle output forwarding completed")
        .into_inner()
        .expect("Gradle output log mutex is not poisoned");

    eprintln!("[docgen] Kotlin vector process finished with {status}");
    if !status.success() {
        panic!(
            "Kotlin documentation vector command failed ({}):\n{}",
            status,
            tail(&log, 12_000)
        );
    }

    let mut test_output = log;
    if !test_output.contains("PROXIMITY_DOC[") {
        let report = repository_root
            .join("kapun-proximity/build/test-results/jvmTest/TEST-org.kapunsdk.proximity.protocol.mdl.ProximityDocumentationVectorTest.xml");
        let report_text = fs::read_to_string(&report).unwrap_or_else(|error| {
            panic!(
                "Gradle did not print fresh test output and the cached report {} is unavailable: {error}",
                report.display(),
            )
        });
        test_output.push_str(
            &extract_test_report_output(&report_text).unwrap_or_else(|| {
                panic!(
                    "Gradle test report {} has no captured stdout",
                    report.display()
                )
            }),
        );
    }

    eprintln!("[docgen] parsing and validating labelled Kotlin payloads");
    let grouped = parse_kotlin_output(&test_output);
    validate_kotlin_examples(&grouped);
    grouped
        .into_iter()
        .map(|(label, fields)| {
            let id = format!("kotlin_{}", slug(&label));
            let payload = json!({
                "source": "kapun-proximity Kotlin/JVM documentation test",
                "test": "ProximityDocumentationVectorTest",
                "label": label,
                "fields": fields,
            });
            ExampleRecord::Kotlin {
                id,
                name: format!("KMP test: {label}"),
                payload,
            }
        })
        .collect()
}

fn extract_test_report_output(report: &str) -> Option<String> {
    let marker = "<system-out><![CDATA[";
    let start = report.find(marker)? + marker.len();
    let end = report[start..].find("]]></system-out>")? + start;
    Some(report[start..end].to_owned())
}

fn stream_child_output<R: Read>(reader: R, log: Arc<Mutex<String>>) {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).unwrap_or(0);
        if bytes_read == 0 {
            break;
        }
        print!("{line}");
        let _ = std::io::stdout().flush();
        log.lock()
            .expect("Gradle output log mutex is not poisoned")
            .push_str(&line);
    }
}

fn parse_kotlin_output(log: &str) -> BTreeMap<String, BTreeMap<String, JsonValue>> {
    let mut grouped = BTreeMap::<String, BTreeMap<String, JsonValue>>::new();
    for line in log.lines() {
        let Some(start) = line.find("PROXIMITY_DOC[") else {
            continue;
        };
        let record = &line[start + "PROXIMITY_DOC[".len()..];
        let Some(label_end) = record.find("]") else {
            continue;
        };
        let label = &record[..label_end];
        let record = &record[label_end + 1..];
        let Some((key, raw_value)) = record
            .strip_prefix('.')
            .and_then(|value| value.split_once('='))
        else {
            continue;
        };
        grouped
            .entry(label.to_owned())
            .or_default()
            .insert(key.to_owned(), parse_kotlin_value(raw_value));
    }
    grouped
}

fn parse_kotlin_value(value: &str) -> JsonValue {
    serde_json::from_str(value).unwrap_or_else(|_| JsonValue::String(value.to_owned()))
}

fn validate_kotlin_examples(grouped: &BTreeMap<String, BTreeMap<String, JsonValue>>) {
    let encryption = grouped
        .get("Encryption")
        .expect("Kotlin vectors must print an Encryption record");
    assert_kotlin_bool(encryption, "decryption_verified", true);

    for label in [
        "Encoded Document-Request",
        "Encoded Document-Response",
        "Normal Flow QR",
        "Normal Flow First Application Message",
        "Reverse Flow QR",
        "Reverse Flow First Application Message",
        "Reverse Flow Second Application Message",
    ] {
        let fields = grouped
            .get(label)
            .unwrap_or_else(|| panic!("Kotlin vectors must print {label}"));
        let cbor_hex = fields
            .get("cbor_hex")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("Kotlin {label} must print cbor_hex"));
        let bytes = decode_hex(cbor_hex).unwrap_or_else(|error| panic!("Kotlin {label}: {error}"));
        let decoded: Value = ciborium::from_reader(bytes.as_slice())
            .unwrap_or_else(|error| panic!("Kotlin {label} is not valid CBOR: {error}"));
        if label == "Reverse Flow First Application Message" {
            assert!(
                !cbor_map_has_integer_key(&decoded, 2),
                "Kotlin reverse-flow DeviceEngagement must omit TransferMethods (key 2)",
            );
        }
    }

    for (label, scanned_model, first_model) in [
        ("Normal Flow", "DeviceEngagement", "SessionEstablishment"),
        ("Reverse Flow", "ReaderEngagement", "DeviceEngagement"),
    ] {
        let fields = grouped
            .get(label)
            .unwrap_or_else(|| panic!("Kotlin vectors must print {label}"));
        assert_eq!(
            fields.get("scanned_qr_model").and_then(JsonValue::as_str),
            Some(scanned_model),
            "Kotlin {label} must identify its QR model",
        );
        assert_eq!(
            fields
                .get("first_application_message_model")
                .and_then(JsonValue::as_str),
            Some(first_model),
            "Kotlin {label} must identify its first application message",
        );
        assert_kotlin_bool(fields, "round_trip_verified", true);
    }
    assert_eq!(
        grouped
            .get("Reverse Flow")
            .and_then(|fields| fields.get("reader_next_message_model"))
            .and_then(JsonValue::as_str),
        Some("SessionEstablishment"),
        "reverse flow must send SessionEstablishment after DeviceEngagement",
    );
    let normal_engagement = grouped
        .get("Normal Flow QR")
        .and_then(|fields| fields.get("cbor_hex"))
        .and_then(JsonValue::as_str)
        .and_then(|value| decode_hex(value).ok())
        .and_then(|bytes| ciborium::from_reader(bytes.as_slice()).ok())
        .expect("normal QR DeviceEngagement must be valid CBOR");
    assert!(
        cbor_map_has_integer_key(&normal_engagement, 2),
        "normal QR DeviceEngagement retains TransferMethods (key 2)",
    );

    let response_fields = grouped
        .get("Encoded Document-Response")
        .expect("Kotlin vectors must print an encoded response");
    let response_bytes = decode_hex(
        response_fields
            .get("cbor_hex")
            .and_then(JsonValue::as_str)
            .expect("Kotlin response must print cbor_hex"),
    )
    .expect("Kotlin response cbor_hex must be valid hex");
    let response: Value = ciborium::from_reader(response_bytes.as_slice())
        .expect("Kotlin response must be valid CBOR");
    let encrypted_response =
        cbor_map_bytes(&response, "data").expect("Kotlin response must contain byte-string data");
    let response_sha = cbor_map_bytes(&response, "shaSum")
        .expect("Kotlin response must contain byte-string shaSum");
    assert_eq!(response_sha, Sha256::digest(encrypted_response).as_slice());

    // The Kotlin test performs both SDK decryptions before emitting this marker. Rust cannot
    // decrypt those random-key ciphertexts independently because the test intentionally never
    // exports ephemeral private keys, so the marker is the cross-language decryption assertion.
}

fn cbor_map_bytes<'a>(value: &'a Value, key: &str) -> Option<&'a [u8]> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries.iter().find_map(|(entry_key, entry_value)| {
        if matches!(entry_key, Value::Text(entry_key) if entry_key == key) {
            match entry_value {
                Value::Bytes(bytes) => Some(bytes.as_slice()),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn cbor_map_has_integer_key(value: &Value, key: i64) -> bool {
    let Value::Map(entries) = value else {
        return false;
    };
    entries
        .iter()
        .any(|(entry_key, _)| entry_key == &integer(key))
}

fn assert_kotlin_bool(fields: &BTreeMap<String, JsonValue>, key: &str, expected: bool) {
    let actual = fields
        .get(key)
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("Kotlin Encryption must print {key}"));
    assert_eq!(
        actual, expected,
        "unexpected Kotlin documentation marker for {key}"
    );
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has an odd length".to_owned());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| format!("invalid hex at byte {index}"))
        })
        .collect()
}

fn slug(value: &str) -> String {
    let mut slug = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('_') {
            slug.push('_');
        }
    }
    slug.trim_matches('_').to_owned()
}

fn tail(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let target = value.len() - max_bytes;
    let start = value
        .char_indices()
        .find(|(index, _)| *index >= target)
        .map(|(index, _)| index)
        .unwrap_or(0);
    value[start..].to_owned()
}

fn generate_data_source(
    models: &[Model],
    model_bundles: &[ModelBundle],
    examples: &[ExampleRecord],
) -> String {
    let model_json = serde_json::to_string_pretty(&models).expect("model JSON is serializable");
    let examples_json = examples_json(examples);
    let empty_flow_payload = JsonValue::Object(Default::default());
    let flow_payload = examples
        .iter()
        .find(|example| example.id() == "end_to_end_flow")
        .map(|example| example.payload())
        .unwrap_or(&empty_flow_payload);
    let mut flow_display = display_json_value(flow_payload);
    if let JsonValue::Object(fields) = &mut flow_display {
        // Step-level example_ref values carry the joins; omit the duplicate summary list from
        // the printed view so this appendix doesn't spill a redundant tail onto another page.
        fields.remove("example_refs");
    }
    let flow_display_json =
        serde_json::to_string_pretty(&flow_display).expect("flow display JSON is serializable");

    let mut source = String::new();
    source.push_str("// Generated by kapun-proximity/documentation. Do not edit this file.\n");
    source.push_str("// Include this file from another Typst document to reuse the data.\n");
    source.push_str(
        "// Regenerate with: cargo run -p kapun-proximity-docgen -- --output-dir ./generated\n\n",
    );
    source.push_str("#let proximity_models = ");
    source.push_str(&typst_models(&models));
    source.push_str("\n\n#let proximity_model_bundles = ");
    source.push_str(&typst_model_bundles(model_bundles));
    source.push_str("\n\n#let proximity_examples = ");
    source.push_str(&typst_examples(&examples));
    source.push_str("\n\n#let proximity_models_json = ");
    source.push_str(&typst_string(&model_json));
    source.push_str("\n#let proximity_examples_json = ");
    source.push_str(&typst_string(&examples_json));
    source.push_str("\n#let proximity_flow_json = ");
    source.push_str(&typst_string(&flow_display_json));
    source.push_str("\n\n");
    source.push_str(flow_typst());
    source
}

fn examples_json(examples: &[ExampleRecord]) -> String {
    serde_json::to_string_pretty(
        &examples
            .iter()
            .map(|example| {
                json!({
                    "id": example.id(),
                    "name": example.name(),
                    "payload": example.payload(),
                })
            })
            .collect::<Vec<_>>(),
    )
    .expect("example JSON is serializable")
}

fn flow_json(examples: &[ExampleRecord]) -> String {
    examples
        .iter()
        .find(|example| example.id() == "end_to_end_flow")
        .map(|example| serde_json::to_string_pretty(example.payload()).expect("flow JSON"))
        .unwrap_or_else(|| "{}".to_owned())
}

/// Long wire values are exact in the sidecar JSON, but are abbreviated in the printed appendix
/// so hexadecimal and base64 strings do not run out of the page. The abbreviated view remains
/// valid JSON and preserves the field name, prefix, suffix, and original character count.
fn display_json_value(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::String(value) if value.chars().count() > 96 => {
            let characters = value.chars().collect::<Vec<_>>();
            let prefix = characters[..48].iter().collect::<String>();
            let suffix = characters[characters.len() - 24..]
                .iter()
                .collect::<String>();
            JsonValue::String(format!(
                "{prefix}…{suffix} ({} characters; full value in sidecar JSON)",
                characters.len()
            ))
        }
        JsonValue::Array(values) => {
            JsonValue::Array(values.iter().map(display_json_value).collect())
        }
        JsonValue::Object(values) => JsonValue::Object(
            values
                .iter()
                .map(|(key, value)| {
                    let displayed = if key == "verification_trace" {
                        json!({
                            "flow_ref": value.get("flow_ref"),
                            "transport_and_crypto_stages_verified": value.get("transport_and_crypto_stages_verified"),
                            "swiss_profile_authentication_fully_exercised": value.get("swiss_profile_authentication_fully_exercised"),
                            "steps": "See the individually labelled trace figures in the verification appendix.",
                        })
                    } else {
                        display_json_value(value)
                    };
                    (key.clone(), displayed)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn generate_text_source() -> String {
    include_str!("../proximity-text-template.typ").to_owned()
}

fn generate_graph_source() -> String {
    include_str!("../proximity-flow-graph.typ").to_owned()
}

fn generate_document_source() -> String {
    "// Generated by kapun-proximity/documentation. Do not edit this file.\n// proximity-text.typ imports the data and reusable CeTZ graph modules.\n\n#include \"proximity-text.typ\"\n".to_owned()
}

fn models() -> Vec<Model> {
    vec![
        model(
            "reader_engagement",
            "ReaderEngagement",
            "CBOR map carried in the QR text mdoc:<base64url(cbor)>",
            &["security", "transfer_methods", "capabilities"],
            "reader_engagement",
            "kotlin_reader_engagement",
            vec![
                field("version", 0, "tstr", false, "SDK version, currently 1.1."),
                field(
                    "security",
                    1,
                    "Security",
                    false,
                    "Cipher suite and ephemeral reader key.",
                ),
                field(
                    "transfer_methods",
                    2,
                    "TransferMethods",
                    true,
                    "Advertised BLE modes and UUIDs.",
                ),
                field(
                    "capabilities",
                    6,
                    "Capabilities",
                    true,
                    "DC API protocol capabilities.",
                ),
            ],
        ),
        model(
            "device_engagement",
            "DeviceEngagement",
            "CBOR map carried in QR or sent as the first reverse-flow application message",
            &["security", "transfer_methods", "capabilities"],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![
                field("version", 0, "tstr", false, "SDK version, currently 1.1."),
                field(
                    "security",
                    1,
                    "Security",
                    false,
                    "Cipher suite and ephemeral device key.",
                ),
                field(
                    "transfer_methods",
                    2,
                    "TransferMethods",
                    true,
                    "Advertised BLE modes and UUIDs; omitted from the reverse-flow wallet message because the transport is already established.",
                ),
                field(
                    "capabilities",
                    6,
                    "Capabilities",
                    true,
                    "DC API protocol capabilities.",
                ),
            ],
        ),
        model(
            "security",
            "Security",
            "CBOR array [cipher suite, tagged COSE_Key bytes]",
            &["cose_key"],
            "reader_engagement",
            "kotlin_reader_engagement",
            vec![
                field("cipher_suite", 0, "uint", false, "1 selects P-256 ECDH."),
                field(
                    "key",
                    1,
                    "#6.24(bstr .cbor COSE_Key)",
                    false,
                    "Tag 24 wraps the CBOR-encoded COSE_Key.",
                ),
            ],
        ),
        model(
            "cose_key",
            "COSE_Key (EC2 / P-256)",
            "CBOR map with COSE key labels",
            &[],
            "reader_engagement",
            "kotlin_reader_engagement",
            vec![
                field("kty", 1, "uint", false, "2 means EC2."),
                field("crv", -1, "uint", false, "1 means P-256."),
                field("x", -2, "bstr", false, "32-byte unsigned x-coordinate."),
                field("y", -3, "bstr", false, "32-byte unsigned y-coordinate."),
            ],
        ),
        model(
            "transfer_methods",
            "TransferMethods",
            "CBOR array of TransferMethod",
            &["transfer_method"],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![field(
                "items",
                "array item",
                "TransferMethod[]",
                false,
                "Zero or more supported transport methods.",
            )],
        ),
        model(
            "transfer_method",
            "TransferMethod",
            "CBOR array [type, version, options]",
            &["ble_options"],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![
                field("type", 0, "uint", false, "2 identifies BLE."),
                field(
                    "version",
                    1,
                    "uint",
                    false,
                    "1 identifies BLE transport version 1.",
                ),
                field(
                    "options",
                    2,
                    "BleOptions",
                    false,
                    "BLE mode flags and UUID values.",
                ),
            ],
        ),
        model(
            "ble_options",
            "BleOptions",
            "CBOR map nested in TransferMethod",
            &[],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![
                field(
                    "peripheral_server_mode_supported",
                    0,
                    "bool",
                    false,
                    "Peripheral-server mode flag.",
                ),
                field(
                    "central_client_mode_supported",
                    1,
                    "bool",
                    false,
                    "Central-client mode flag.",
                ),
                field(
                    "peripheral_server_uuid",
                    10,
                    "bstr (16 bytes)",
                    true,
                    "UUID bytes when peripheral mode is supported.",
                ),
                field(
                    "central_client_uuid",
                    11,
                    "bstr (16 bytes)",
                    true,
                    "UUID bytes when central mode is supported.",
                ),
            ],
        ),
        model(
            "capabilities",
            "Capabilities",
            "CBOR map of capability key to value",
            &["dc_api_support"],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![field(
                "DCv1",
                "0x44437631",
                "DcApiSupport",
                true,
                "ASCII DCv1 capability key.",
            )],
        ),
        model(
            "dc_api_support",
            "DcApiSupport",
            "CBOR array of supported DC API protocol names",
            &["dc_api_protocol"],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![field(
                "protocols",
                "array item",
                "DcApiProtocol[]",
                false,
                "Ordered list of supported protocols.",
            )],
        ),
        model(
            "dc_api_protocol",
            "DcApiProtocol",
            "CBOR text string",
            &[],
            "device_engagement",
            "kotlin_normal_flow_qr",
            vec![field(
                "protocol",
                "array item",
                "tstr",
                false,
                "For example openid4vp-v1-signed.",
            )],
        ),
        model(
            "session_establishment",
            "SessionEstablishment",
            "CBOR map sent by reader with the encrypted request",
            &["cose_key"],
            "encoded_request",
            "kotlin_encoded_document_request",
            vec![
                field(
                    "eReaderKey",
                    "eReaderKey",
                    "#6.24(bstr .cbor COSE_Key)",
                    false,
                    "Ephemeral reader public key.",
                ),
                field(
                    "data",
                    "data",
                    "bstr",
                    false,
                    "AES-256-GCM ciphertext including its 16-byte tag.",
                ),
                field(
                    "dcApiSelected",
                    "dcApiSelected",
                    "bool",
                    true,
                    "SDK extension identifying the DC API path.",
                ),
            ],
        ),
        model(
            "session_data",
            "SessionData",
            "CBOR map returned by wallet with encrypted response",
            &[],
            "encoded_response",
            "kotlin_encoded_document_response",
            vec![
                field(
                    "data",
                    "data",
                    "bstr / null",
                    true,
                    "Encrypted response bytes or null for a terminal response.",
                ),
                field(
                    "status",
                    "status",
                    "uint / null",
                    true,
                    "Termination status; normally absent on success.",
                ),
                field(
                    "shaSum",
                    "shaSum",
                    "bstr / null",
                    true,
                    "Swiss/debug SHA-256 extension; not generic ISO model data.",
                ),
                field(
                    "dcApiSelected",
                    "dcApiSelected",
                    "bool / null",
                    true,
                    "SDK extension indicating DC API selection.",
                ),
            ],
        ),
        model(
            "session_transcript",
            "SessionTranscript",
            "CBOR array, wrapped in tag 24 for KDF and origin",
            &["device_engagement", "cose_key"],
            "encryption",
            "kotlin_encryption",
            vec![
                field(
                    "device_engagement",
                    0,
                    "#6.24(bstr .cbor DeviceEngagement)",
                    false,
                    "Wallet engagement, including reverse engagement response.",
                ),
                field(
                    "eReaderKey",
                    1,
                    "#6.24(bstr .cbor COSE_Key)",
                    false,
                    "Ephemeral reader key.",
                ),
                field(
                    "handover",
                    2,
                    "null",
                    false,
                    "BLE handover value in these examples.",
                ),
            ],
        ),
        model(
            "ecdh_key_material",
            "EcdhKeyMaterial (documentation vector)",
            "P-256 keys and derived ISO session keys",
            &["session_transcript"],
            "encryption",
            "kotlin_encryption",
            vec![
                field(
                    "reader_private_scalar",
                    "documentation-only",
                    "bstr (32 bytes)",
                    false,
                    "Fixed documentation value only; never use in production.",
                ),
                field(
                    "device_private_scalar",
                    "documentation-only",
                    "bstr (32 bytes)",
                    false,
                    "Fixed documentation value only; never use in production.",
                ),
                field(
                    "reader_public_key_sec1",
                    "derived",
                    "bstr (65 bytes)",
                    false,
                    "Uncompressed SEC1 P-256 public key.",
                ),
                field(
                    "device_public_key_sec1",
                    "derived",
                    "bstr (65 bytes)",
                    false,
                    "Uncompressed SEC1 P-256 public key.",
                ),
                field(
                    "shared_secret",
                    "derived",
                    "bstr (32 bytes)",
                    false,
                    "ECDH raw secret Z_ab; this is the key material passed as HKDF input key material.",
                ),
                field(
                    "key_material",
                    "derived",
                    "bstr (32 bytes)",
                    false,
                    "Alias for the ECDH shared secret when shown as HKDF input key material.",
                ),
                field(
                    "sk_reader / sk_device",
                    "derived",
                    "bstr (32 bytes)",
                    false,
                    "Role-separated AES keys.",
                ),
            ],
        ),
        model(
            "dc_api_request",
            "DC API Request Envelope",
            "UTF-8 JSON inside encrypted SessionEstablishment.data",
            &["dc_api_request_item", "dc_api_request_data"],
            "encryption",
            "kotlin_encryption",
            vec![field(
                "requests",
                "requests",
                "DcApiRequestItem[]",
                false,
                "The SDK consumes the first request.",
            )],
        ),
        model(
            "dc_api_request_item",
            "DC API Request Item",
            "JSON object",
            &["dc_api_request_data"],
            "encryption",
            "kotlin_encryption",
            vec![
                field(
                    "protocol",
                    "protocol",
                    "tstr",
                    false,
                    "openid4vp-v1-signed in this sample.",
                ),
                field(
                    "data",
                    "data",
                    "DcApiRequestData",
                    false,
                    "Protocol-specific request object.",
                ),
            ],
        ),
        model(
            "dc_api_request_data",
            "DC API Request Data",
            "JSON object",
            &[],
            "encryption",
            "kotlin_encryption",
            vec![field(
                "request",
                "request",
                "tstr",
                false,
                "Complete signed request JWT (sample token is illustrative).",
            )],
        ),
        model(
            "swiss_verifier_inputs",
            "SwissVerifierAuthenticationInputs",
            "OpenID4VP request JWT claims/header inputs",
            &["verifier_attestation"],
            "encoded_request",
            "kotlin_encryption",
            vec![
                field(
                    "expected_origins",
                    "expected_origins",
                    "tstr[]",
                    false,
                    "Must include the transcript-derived ISO origin.",
                ),
                field(
                    "verifier_info",
                    "verifier_info",
                    "JSON value[]",
                    true,
                    "Verifier information validated by the Swiss profile.",
                ),
                field(
                    "verifier_attestations",
                    "jwt header / profile input",
                    "VerifierAttestation[]",
                    true,
                    "Attestations validated according to Swiss OID4VP.",
                ),
                field(
                    "response_mode",
                    "response_mode",
                    "tstr",
                    false,
                    "Profile-required value is dc_api.jwt.",
                ),
            ],
        ),
        model(
            "verifier_attestation",
            "VerifierAttestation",
            "JWS / OID4VP profile object",
            &[],
            "encoded_request",
            "kotlin_encryption",
            vec![field(
                "jwt",
                "JWS header / profile value",
                "tstr",
                false,
                "Attestation data is profile-defined; fixtures use an explicit placeholder.",
            )],
        ),
    ]
}

fn model(
    id: &'static str,
    name: &'static str,
    encoding: &'static str,
    dependencies: &[&'static str],
    example_ref: &'static str,
    kotlin_example_ref: &'static str,
    fields: Vec<Field>,
) -> Model {
    Model {
        id,
        name,
        encoding,
        dependencies: dependencies.to_vec(),
        example_ref,
        kotlin_example_ref,
        fields,
    }
}

fn model_bundles(models: &[Model]) -> Vec<ModelBundle> {
    let roots = [
        ("reader_engagement", "ReaderEngagement wire structure"),
        ("device_engagement", "DeviceEngagement wire structure"),
        ("session_establishment", "Encrypted request structures"),
        ("session_data", "Encrypted response structures"),
        (
            "session_transcript",
            "Session transcript and key derivation",
        ),
        (
            "ecdh_key_material",
            "ECDH key material and derived session keys",
        ),
        ("dc_api_request", "DC API request payload"),
        (
            "swiss_verifier_inputs",
            "Swiss verifier authentication inputs",
        ),
    ];
    roots
        .into_iter()
        .map(|(root_id, title)| {
            let root = models
                .iter()
                .find(|model| model.id == root_id)
                .unwrap_or_else(|| panic!("missing model bundle root {root_id}"));
            let mut model_ids = Vec::new();
            collect_model_dependencies(root_id, models, &mut model_ids);
            ModelBundle {
                id: root_id,
                title,
                model_ids,
                example_ref: root.example_ref,
                kotlin_example_ref: root.kotlin_example_ref,
            }
        })
        .collect()
}

fn collect_model_dependencies(
    id: &'static str,
    models: &[Model],
    collected: &mut Vec<&'static str>,
) {
    if collected.contains(&id) {
        return;
    }
    collected.push(id);
    let model = models
        .iter()
        .find(|model| model.id == id)
        .unwrap_or_else(|| panic!("model dependency {id} is not defined"));
    for dependency in &model.dependencies {
        collect_model_dependencies(dependency, models, collected);
    }
}

fn field(
    name: &'static str,
    cbor_key: impl Into<JsonValue>,
    wire_type: &'static str,
    optional: bool,
    description: &'static str,
) -> Field {
    Field {
        name,
        cbor_key: cbor_key.into(),
        wire_type,
        optional,
        description,
    }
}

fn examples() -> Vec<Example> {
    // Fixed private scalars make the generated documentation reproducible. They are only
    // documentation vectors and must never be used as application keys.
    let reader_private = [0x01_u8; 32];
    let device_private = [0x02_u8; 32];
    let reader_secret = SecretKey::from_slice(&reader_private).expect("valid reader scalar");
    let device_secret = SecretKey::from_slice(&device_private).expect("valid device scalar");
    let reader_public = reader_secret.public_key().to_sec1_bytes().to_vec();
    let device_public = device_secret.public_key().to_sec1_bytes().to_vec();
    let shared_secret = diffie_hellman(
        reader_secret.to_nonzero_scalar(),
        device_secret.public_key().as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();

    let reader_cose_key = cose_key_from_p256_public_key(&reader_public);
    let device_cose_key = cose_key_from_p256_public_key(&device_public);
    let reader_engagement = engagement(&reader_cose_key, true, false);
    let device_engagement = engagement(&device_cose_key, false, true);
    let reverse_device_engagement = engagement_without_transfer_methods(&device_cose_key);
    let reader_engagement_bytes = cbor(&reader_engagement);
    let device_engagement_bytes = cbor(&device_engagement);
    let reverse_device_engagement_bytes = cbor(&reverse_device_engagement);
    let e_reader_key_bytes = cbor(&reader_cose_key);

    // In the device-engagement flow the wallet engagement is the first transcript item. In the
    // reader-engagement flow the wallet sends this same DeviceEngagement back before encryption.
    let session_transcript = Value::Array(vec![
        Value::Tag(24, Box::new(Value::Bytes(device_engagement_bytes.clone()))),
        Value::Tag(24, Box::new(Value::Bytes(e_reader_key_bytes.clone()))),
        Value::Null,
    ]);
    let session_transcript_bytes = cbor(&Value::Tag(
        24,
        Box::new(Value::Bytes(cbor(&session_transcript))),
    ));
    let origin_hash = Sha256::digest(&cbor(&session_transcript));
    let origin = format!("iso-18013-5://{}", URL_SAFE_NO_PAD.encode(origin_hash));

    let reader_key = hkdf_iso_180135(&shared_secret, &session_transcript_bytes, Role::SkReader);
    let device_key = hkdf_iso_180135(&shared_secret, &session_transcript_bytes, Role::SkDevice);
    let request_plaintext = br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{"request":"eyJhbGciOiJFUzI1NiJ9.docs-example"}}]}"#;
    let response_plaintext = br#"{"vp_token":["example-sd-jwt"]}"#;
    let encrypted_request =
        encrypt_epoch_iso_180135(request_plaintext, &reader_key, Role::SkReader, 1)
            .expect("fixed AES key is valid");
    let encrypted_response =
        encrypt_epoch_iso_180135(response_plaintext, &device_key, Role::SkDevice, 1)
            .expect("fixed AES key is valid");
    let reverse_session_transcript = Value::Array(vec![
        Value::Tag(
            24,
            Box::new(Value::Bytes(reverse_device_engagement_bytes.clone())),
        ),
        Value::Tag(24, Box::new(Value::Bytes(e_reader_key_bytes.clone()))),
        Value::Null,
    ]);
    let reverse_session_transcript_bytes = cbor(&Value::Tag(
        24,
        Box::new(Value::Bytes(cbor(&reverse_session_transcript))),
    ));
    let reverse_origin_hash = Sha256::digest(&cbor(&reverse_session_transcript));
    let reverse_origin = format!(
        "iso-18013-5://{}",
        URL_SAFE_NO_PAD.encode(reverse_origin_hash)
    );
    let reverse_reader_key = hkdf_iso_180135(
        &shared_secret,
        &reverse_session_transcript_bytes,
        Role::SkReader,
    );
    let reverse_device_key = hkdf_iso_180135(
        &shared_secret,
        &reverse_session_transcript_bytes,
        Role::SkDevice,
    );
    let reverse_encrypted_request =
        encrypt_epoch_iso_180135(request_plaintext, &reverse_reader_key, Role::SkReader, 1)
            .expect("fixed reverse-flow AES key is valid");
    let reverse_encrypted_response =
        encrypt_epoch_iso_180135(response_plaintext, &reverse_device_key, Role::SkDevice, 1)
            .expect("fixed reverse-flow AES key is valid");
    let reverse_establishment = Value::Map(vec![
        (
            text("eReaderKey"),
            Value::Tag(24, Box::new(Value::Bytes(e_reader_key_bytes.clone()))),
        ),
        (
            text("data"),
            Value::Bytes(reverse_encrypted_request.clone()),
        ),
        (text("dcApiSelected"), Value::Bool(true)),
    ]);
    let reverse_response = Value::Map(vec![
        (
            text("data"),
            Value::Bytes(reverse_encrypted_response.clone()),
        ),
        (
            text("shaSum"),
            Value::Bytes(Sha256::digest(&reverse_encrypted_response).to_vec()),
        ),
        (text("dcApiSelected"), Value::Bool(true)),
    ]);

    let establishment = Value::Map(vec![
        (
            text("eReaderKey"),
            Value::Tag(24, Box::new(Value::Bytes(e_reader_key_bytes.clone()))),
        ),
        (text("data"), Value::Bytes(encrypted_request.clone())),
        (text("dcApiSelected"), Value::Bool(true)),
    ]);
    let response = Value::Map(vec![
        (text("data"), Value::Bytes(encrypted_response.clone())),
        (
            text("shaSum"),
            Value::Bytes(Sha256::digest(&encrypted_response).to_vec()),
        ),
        (text("dcApiSelected"), Value::Bool(true)),
    ]);
    let normal_verification = flow_verification_trace(
        "normal_flow",
        "device-engagement",
        &reader_engagement,
        &reader_engagement_bytes,
        &device_engagement,
        &device_engagement_bytes,
        &reader_public,
        &device_public,
        &shared_secret,
        &reader_key,
        &device_key,
        &session_transcript,
        &session_transcript_bytes,
        &origin,
        request_plaintext,
        &encrypted_request,
        &establishment,
        response_plaintext,
        &encrypted_response,
        &response,
    );
    let reverse_verification = flow_verification_trace(
        "reverse_flow",
        "reader-engagement",
        &reader_engagement,
        &reader_engagement_bytes,
        &reverse_device_engagement,
        &reverse_device_engagement_bytes,
        &reader_public,
        &device_public,
        &shared_secret,
        &reverse_reader_key,
        &reverse_device_key,
        &reverse_session_transcript,
        &reverse_session_transcript_bytes,
        &reverse_origin,
        request_plaintext,
        &reverse_encrypted_request,
        &reverse_establishment,
        response_plaintext,
        &reverse_encrypted_response,
        &reverse_response,
    );

    vec![
        Example {
            id: "reader_engagement",
            name: "Reader Engagement",
            payload: json!({
                "qr_prefix": "mdoc:",
                "cbor_hex": hex(&reader_engagement_bytes),
                "base64url": URL_SAFE_NO_PAD.encode(&reader_engagement_bytes),
                "public_key_sec1_hex": hex(&reader_public),
                "cose_key_cbor_hex": hex(&cbor(&reader_cose_key)),
                "role": "reader; the wallet sends a DeviceEngagement back before session encryption",
                "diagnostic": {
                    "0": "1.1",
                    "1": [1, "tag(24, bstr(cbor(COSE_Key)))"],
                    "2": [[2, 1, {"0": false, "1": true, "11": hex(&central_uuid())}]],
                    "6": {"1145271857": ["openid4vp-v1-signed"]}
                },
            }),
        },
        Example {
            id: "device_engagement",
            name: "Device Engagement (Normal Flow QR)",
            payload: json!({
                "qr_prefix": "mdoc:",
                "cbor_hex": hex(&device_engagement_bytes),
                "base64url": URL_SAFE_NO_PAD.encode(&device_engagement_bytes),
                "public_key_sec1_hex": hex(&device_public),
                "cose_key_cbor_hex": hex(&cbor(&device_cose_key)),
                "role": "device; advertised by the wallet for the reader to scan in normal flow",
                "transfer_methods_present": true,
                "diagnostic": {
                    "0": "1.1",
                    "1": [1, "tag(24, bstr(cbor(COSE_Key)))"],
                    "2": [[2, 1, {"0": true, "1": false, "10": hex(&peripheral_uuid())}]],
                    "6": {"1145271857": ["openid4vp-v1-signed"]}
                },
            }),
        },
        Example {
            id: "reverse_device_engagement",
            name: "Device Engagement (Reverse Flow First Application Message)",
            payload: json!({
                "model": "DeviceEngagement",
                "encoding": "CBOR map; raw CBOR is the first reverse-flow BLE application message",
                "cbor_hex": hex(&reverse_device_engagement_bytes),
                "base64url": URL_SAFE_NO_PAD.encode(&reverse_device_engagement_bytes),
                "public_key_sec1_hex": hex(&device_public),
                "cose_key_cbor_hex": hex(&cbor(&device_cose_key)),
                "role": "wallet; sent after scanning ReaderEngagement and connecting",
                "transfer_methods_present": false,
                "transfer_methods_omitted_reason": "createReverse supplies null central-client and peripheral-server UUIDs; the established ReaderEngagement transport already identifies the connection",
                "diagnostic": {
                    "0": "1.1",
                    "1": [1, "tag(24, bstr(cbor(COSE_Key)))"],
                    "6": {"1145271857": ["openid4vp-v1-signed"]}
                },
            }),
        },
        Example {
            id: "normal_flow",
            name: "Normal Flow (Scan DeviceEngagement)",
            payload: json!({
                "initiator": "wallet",
                "qr_payload": {
                    "model": "DeviceEngagement",
                    "qr": format!("mdoc:{}", URL_SAFE_NO_PAD.encode(&device_engagement_bytes)),
                    "cbor_hex": hex(&device_engagement_bytes),
                },
                "after_ble_connection": {
                    "reader_action": "derive the session cipher from DeviceEngagement and eReaderKey",
                    "first_application_message_model": "SessionEstablishment",
                    "first_application_message_cbor_hex": hex(&cbor(&establishment)),
                    "first_application_message_base64url": URL_SAFE_NO_PAD.encode(cbor(&establishment)),
                },
                "verification_trace": normal_verification,
                "example_refs": ["device_engagement", "encoded_request", "encryption", "encoded_response"],
                "session_transcript_outer_hex": hex(&session_transcript_bytes),
                "origin": origin,
                "request_plaintext_utf8": String::from_utf8_lossy(request_plaintext),
                "decoded_request_claims": openid4vp_request_claims(&origin),
            }),
        },
        Example {
            id: "reverse_flow",
            name: "Reverse Flow (Scan ReaderEngagement; First Bytes Are DeviceEngagement)",
            payload: json!({
                "initiator": "reader",
                "qr_payload": {
                    "model": "ReaderEngagement",
                    "qr": format!("mdoc:{}", URL_SAFE_NO_PAD.encode(&reader_engagement_bytes)),
                    "cbor_hex": hex(&reader_engagement_bytes),
                },
                "after_ble_connection": {
                    "wallet_action": "send DeviceEngagement before any encrypted session data",
                    "first_application_message_model": "DeviceEngagement",
                    "first_application_message_cbor_hex": hex(&reverse_device_engagement_bytes),
                    "first_application_message_base64url": URL_SAFE_NO_PAD.encode(&reverse_device_engagement_bytes),
                    "reader_action_after_first_message": "parse DeviceEngagement, derive the session cipher, then send SessionEstablishment",
                    "second_application_message_model": "SessionEstablishment",
                    "second_application_message_cbor_hex": hex(&cbor(&reverse_establishment)),
                },
                "verification_trace": reverse_verification,
                "example_refs": ["reader_engagement", "reverse_device_engagement", "encoded_request_reverse", "encryption_reverse", "encoded_response_reverse"],
                "session_transcript_outer_hex": hex(&reverse_session_transcript_bytes),
                "origin": reverse_origin,
                "request_plaintext_utf8": String::from_utf8_lossy(request_plaintext),
                "decoded_request_claims": openid4vp_request_claims(&reverse_origin),
            }),
        },
        Example {
            id: "encoded_request_reverse",
            name: "Encoded Document-Request (Reverse Flow)",
            payload: json!({
                "model": "SessionEstablishment",
                "cbor_hex": hex(&cbor(&reverse_establishment)),
                "base64url": URL_SAFE_NO_PAD.encode(cbor(&reverse_establishment)),
                "fields": {
                    "eReaderKey_cbor_hex": hex(&e_reader_key_bytes),
                    "device_engagement_cbor_hex": hex(&reverse_device_engagement_bytes),
                    "session_transcript_outer_hex": hex(&reverse_session_transcript_bytes),
                    "origin": reverse_origin,
                    "data_ciphertext_hex": hex(&reverse_encrypted_request),
                    "dcApiSelected": true,
                    "plaintext_utf8": String::from_utf8_lossy(request_plaintext),
                    "decoded_request_claims": openid4vp_request_claims(&reverse_origin),
                },
            }),
        },
        Example {
            id: "encoded_response_reverse",
            name: "Encoded Document-Response (Reverse Flow)",
            payload: json!({
                "model": "SessionData",
                "cbor_hex": hex(&cbor(&reverse_response)),
                "base64url": URL_SAFE_NO_PAD.encode(cbor(&reverse_response)),
                "fields": {
                    "data_ciphertext_hex": hex(&reverse_encrypted_response),
                    "session_transcript_outer_hex": hex(&reverse_session_transcript_bytes),
                    "origin": reverse_origin,
                    "shaSum_hex": hex(&Sha256::digest(&reverse_encrypted_response)),
                    "dcApiSelected": true,
                    "plaintext_utf8": String::from_utf8_lossy(response_plaintext),
                },
            }),
        },
        Example {
            id: "encryption_reverse",
            name: "Encryption Examples (Reverse Flow)",
            payload: json!({
                "documentation_only_reader_private_scalar_hex": hex(&reader_private),
                "documentation_only_device_private_scalar_hex": hex(&device_private),
                "reader_public_key_sec1_hex": hex(&reader_public),
                "device_public_key_sec1_hex": hex(&device_public),
                "origin": reverse_origin,
                "device_engagement_cbor_hex": hex(&reverse_device_engagement_bytes),
                "reader_engagement_cbor_hex": hex(&reader_engagement_bytes),
                "session_transcript_outer_hex": hex(&reverse_session_transcript_bytes),
                "shared_secret_hex": hex(&shared_secret),
                "key_material_hex": hex(&shared_secret),
                "key_material_description": "ECDH Z_ab; input key material (IKM) for HKDF-SHA-256",
                "sk_reader_hex": hex(&reverse_reader_key),
                "sk_device_hex": hex(&reverse_device_key),
                "reader_epoch": 1,
                "device_epoch": 1,
                "request_plaintext_utf8": String::from_utf8_lossy(request_plaintext),
                "request_ciphertext_hex": hex(&reverse_encrypted_request),
                "response_plaintext_utf8": String::from_utf8_lossy(response_plaintext),
                "response_ciphertext_hex": hex(&reverse_encrypted_response),
                "note": "The private scalars are fixed documentation values. Production derives shared_secret by ECDH before applying the same ISO 18013-5 HKDF and AES-256-GCM functions.",
            }),
        },
        Example {
            id: "encoded_request",
            name: "Encoded Document-Request",
            payload: json!({
                "model": "SessionEstablishment",
                "cbor_hex": hex(&cbor(&establishment)),
                "base64url": URL_SAFE_NO_PAD.encode(cbor(&establishment)),
                "fields": {
                    "eReaderKey_cbor_hex": hex(&e_reader_key_bytes),
                    "device_engagement_cbor_hex": hex(&device_engagement_bytes),
                    "session_transcript_outer_hex": hex(&session_transcript_bytes),
                    "origin": origin,
                    "data_ciphertext_hex": hex(&encrypted_request),
                    "dcApiSelected": true,
                    "plaintext_utf8": String::from_utf8_lossy(request_plaintext),
                    "decoded_request_claims": openid4vp_request_claims(&origin),
                },
            }),
        },
        Example {
            id: "encoded_response",
            name: "Encoded Document-Response",
            payload: json!({
                "model": "SessionData",
                "cbor_hex": hex(&cbor(&response)),
                "base64url": URL_SAFE_NO_PAD.encode(cbor(&response)),
                "fields": {
                    "data_ciphertext_hex": hex(&encrypted_response),
                    "session_transcript_outer_hex": hex(&session_transcript_bytes),
                    "origin": origin,
                    "shaSum_hex": hex(&Sha256::digest(&encrypted_response)),
                    "dcApiSelected": true,
                    "plaintext_utf8": String::from_utf8_lossy(response_plaintext),
                },
            }),
        },
        Example {
            id: "encryption",
            name: "Encryption Examples",
            payload: json!({
                "documentation_only_reader_private_scalar_hex": hex(&reader_private),
                "documentation_only_device_private_scalar_hex": hex(&device_private),
                "reader_public_key_sec1_hex": hex(&reader_public),
                "device_public_key_sec1_hex": hex(&device_public),
                "origin": origin,
                "device_engagement_cbor_hex": hex(&device_engagement_bytes),
                "reader_engagement_cbor_hex": hex(&reader_engagement_bytes),
                "session_transcript_outer_hex": hex(&session_transcript_bytes),
                "shared_secret_hex": hex(&shared_secret),
                "key_material_hex": hex(&shared_secret),
                "key_material_description": "ECDH Z_ab; input key material (IKM) for HKDF-SHA-256",
                "sk_reader_hex": hex(&reader_key),
                "sk_device_hex": hex(&device_key),
                "reader_epoch": 1,
                "device_epoch": 1,
                "request_plaintext_utf8": String::from_utf8_lossy(request_plaintext),
                "request_ciphertext_hex": hex(&encrypted_request),
                "response_plaintext_utf8": String::from_utf8_lossy(response_plaintext),
                "response_ciphertext_hex": hex(&encrypted_response),
                "note": "The private scalars are fixed documentation values. Production derives shared_secret by ECDH before applying the same ISO 18013-5 HKDF and AES-256-GCM functions.",
            }),
        },
        Example {
            id: "end_to_end_flow",
            name: "End-to-End Verification Flow",
            payload: end_to_end_flow_payload(
                &origin,
                &session_transcript_bytes,
                &reverse_origin,
                &reverse_session_transcript_bytes,
            ),
        },
    ]
}

fn flow_verification_trace(
    flow_id: &str,
    engagement_flow: &str,
    reader_engagement: &Value,
    reader_engagement_bytes: &[u8],
    device_engagement: &Value,
    device_engagement_bytes: &[u8],
    reader_public: &[u8],
    device_public: &[u8],
    shared_secret: &[u8],
    reader_key: &[u8],
    device_key: &[u8],
    session_transcript: &Value,
    session_transcript_outer: &[u8],
    origin: &str,
    request_plaintext: &[u8],
    request_ciphertext: &[u8],
    request_envelope: &Value,
    response_plaintext: &[u8],
    response_ciphertext: &[u8],
    response_envelope: &Value,
) -> JsonValue {
    let reverse = engagement_flow == "reader-engagement";
    let (qr_model, qr_value, qr_bytes, qr_public) = if reverse {
        (
            "ReaderEngagement",
            reader_engagement,
            reader_engagement_bytes,
            reader_public,
        )
    } else {
        (
            "DeviceEngagement",
            device_engagement,
            device_engagement_bytes,
            device_public,
        )
    };
    let qr = format!("mdoc:{}", URL_SAFE_NO_PAD.encode(qr_bytes));
    let qr_decoded_bytes = URL_SAFE_NO_PAD
        .decode(qr.strip_prefix("mdoc:").expect("QR has mdoc prefix"))
        .expect("engagement QR base64url decodes");
    assert_eq!(
        qr_decoded_bytes, qr_bytes,
        "{flow_id}: QR recovers engagement CBOR"
    );
    let qr_decoded_model = decode_cbor(&qr_decoded_bytes);
    assert_eq!(
        &qr_decoded_model, qr_value,
        "{flow_id}: QR CBOR decodes to engagement"
    );

    let qr_step = json!({
        "id": format!("{flow_id}.engagement_qr"),
        "example_ref": if reverse { "reader_engagement" } else { "device_engagement" },
        "source_refs": ["kotlin_engagement_qr_decode", "kotlin_engagement_encode", "kotlin_doc_test_flow_variants"],
        "step": 1,
        "name": format!("Scan {qr_model}"),
        "direction": if reverse { "reader -> wallet" } else { "wallet -> reader" },
        "payload": engagement_semantic_payload(qr_model, qr_public, true),
        "encoding": {
            "format": "CBOR",
            "cbor_hex": hex(qr_bytes),
            "base64url_without_padding": URL_SAFE_NO_PAD.encode(qr_bytes),
            "value_matches_cbor_decode": true,
        },
        "transport": {
            "kind": "QR text",
            "value": qr,
            "prefix": "mdoc:",
            "base64url_decode_matches_cbor": true,
        },
        "decoding": {
            "model": qr_model,
            "cbor_decode_matches_payload": true,
            "public_key_sec1_hex": hex(qr_public),
        },
    });

    let mut steps = vec![qr_step];
    if reverse {
        let decoded_device_engagement = decode_cbor(device_engagement_bytes);
        assert_eq!(decoded_device_engagement, *device_engagement);
        assert!(
            !cbor_map_has_integer_key(&decoded_device_engagement, 2),
            "reverse DeviceEngagement omits TransferMethods (CBOR key 2)"
        );
        steps.push(json!({
            "id": "reverse_flow.device_engagement_first_message",
            "example_ref": "reverse_device_engagement",
            "source_refs": ["kotlin_reverse_engagement_builder", "kotlin_send_device_engagement", "kotlin_verifier_reverse_and_response", "kotlin_doc_test_flow_variants"],
            "step": 2,
            "name": "Wallet sends DeviceEngagement as first BLE application message",
            "direction": "wallet -> reader",
            "mode_selection": "fixture choice: wallet peripheral-server / reader central-client; deployment may choose the inverse",
            "payload": engagement_semantic_payload("DeviceEngagement", device_public, false),
            "encoding": {
                "format": "CBOR",
                "cbor_hex": hex(device_engagement_bytes),
                "transport_bytes_hex": hex(device_engagement_bytes),
                "value_matches_cbor_decode": true,
            },
            "decoding": {
                "model": "DeviceEngagement",
                "cbor_decode_matches_payload": true,
                "public_key_sec1_hex": hex(device_public),
                "transfer_methods_key_2_present": false,
            },
        }));
    } else {
        steps.push(json!({
            "id": "normal_flow.ble_connection",
            "example_ref": "device_engagement",
            "source_refs": ["kotlin_verifier_engagement_scan"],
            "step": 2,
            "name": "Reader scans DeviceEngagement, connects, and signals readiness",
            "direction": "reader -> wallet",
            "transport": "BLE GATT; readiness is signalled through State after characteristic subscriptions",
            "selected_mode": "wallet peripheral-server / reader central-client",
            "mode_selection": "implementation choice, not an ISO-mandated fixed direction; Android and GATT database trade-offs may favor the inverse",
            "engagement_cbor_was_decoded_before_connection": true,
            "ble_mode_flags_verified": {
                "device_peripheral_server_mode_supported": true,
                "device_central_client_mode_supported": false,
            },
        }));
    }

    let reader_secret = SecretKey::from_slice(&[0x01_u8; 32]).expect("reader scalar is valid");
    let device_secret = SecretKey::from_slice(&[0x02_u8; 32]).expect("device scalar is valid");
    let reader_side_shared = diffie_hellman(
        reader_secret.to_nonzero_scalar(),
        device_secret.public_key().as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();
    let device_side_shared = diffie_hellman(
        device_secret.to_nonzero_scalar(),
        reader_secret.public_key().as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();
    assert_eq!(reader_side_shared, device_side_shared);
    assert_eq!(reader_side_shared, shared_secret);
    assert_eq!(
        hkdf_iso_180135(
            &reader_side_shared,
            session_transcript_outer,
            Role::SkReader
        ),
        reader_key,
    );
    assert_eq!(
        hkdf_iso_180135(
            &device_side_shared,
            session_transcript_outer,
            Role::SkDevice
        ),
        device_key,
    );
    let transcript_decoded = decode_cbor(session_transcript_outer);
    assert_eq!(
        transcript_decoded,
        Value::Tag(24, Box::new(Value::Bytes(cbor(session_transcript))))
    );
    steps.push(json!({
        "id": format!("{flow_id}.session_transcript_and_keys"),
        "example_ref": if reverse { "encryption_reverse" } else { "encryption" },
        "source_refs": ["kotlin_session_transcript_ecdh", "rust_iso_ecdh_key_material", "rust_iso_hkdf", "kotlin_doc_test_flow_round_trip"],
        "step": 3,
        "name": "Build SessionTranscript and derive matching session keys",
        "direction": "reader and wallet",
        "encoding": {
            "session_transcript_model": "[tag24(DeviceEngagement), tag24(eReaderKey), null]",
            "session_transcript_cbor_hex": hex(&cbor(session_transcript)),
            "session_transcript_outer_hex": hex(session_transcript_outer),
            "origin": origin,
        },
        "ecdh": {
            "documentation_only_reader_private_scalar_hex": hex(&[0x01_u8; 32]),
            "documentation_only_device_private_scalar_hex": hex(&[0x02_u8; 32]),
            "reader_public_key_sec1_hex": hex(reader_public),
            "device_public_key_sec1_hex": hex(device_public),
            "reader_ecdh_shared_secret_hex": hex(&reader_side_shared),
            "device_ecdh_shared_secret_hex": hex(&device_side_shared),
            "key_material_hex": hex(&reader_side_shared),
            "key_material_is_hkdf_ikm": true,
            "both_peers_derive_same_secret": true,
        },
        "key_derivation": {
            "algorithm": "HKDF-SHA-256, ISO 18013-5 role labels",
            "input_key_material_hex": hex(&reader_side_shared),
            "sk_reader_hex": hex(reader_key),
            "sk_device_hex": hex(device_key),
            "both_peer_derivations_verified": true,
        },
        "decoding": {
            "session_transcript_cbor_round_trip_verified": true,
        },
    }));

    steps.push(message_verification_step(
        flow_id,
        4,
        "reader_request",
        "Reader sends encrypted SessionEstablishment request",
        "SessionEstablishment",
        request_plaintext,
        request_ciphertext,
        request_envelope,
        reader_key,
        Role::SkReader,
    ));
    steps.push(json!({
        "id": format!("{flow_id}.swiss_reader_authentication"),
        "example_ref": if reverse { "encoded_request_reverse" } else { "encoded_request" },
        "source_refs": ["kotlin_wallet_request_decryption"],
        "step": 5,
        "name": "Wallet validates the Swiss OID4VP verifier and request before consent",
        "direction": "wallet local validation",
        "decoded_request_claims": openid4vp_request_claims(origin),
        "expected_origin_matches_session_transcript": true,
        "required_response_mode": "dc_api.jwt",
        "verifier_attestation_validation_status": "not_exercised: fixture contains an illustrative placeholder, not a signed Swiss verifier attestation",
        "signature_validation_asserted": false,
        "why_not_fully_exercised": "A cryptographically valid Swiss verifier-attestation fixture and trust configuration are not present in this repository's proximity test vectors.",
    }));
    steps.push(message_verification_step(
        flow_id,
        6,
        "wallet_response",
        "Wallet returns encrypted SessionData response",
        "SessionData",
        response_plaintext,
        response_ciphertext,
        response_envelope,
        device_key,
        Role::SkDevice,
    ));

    json!({
        "schema_version": 1,
        "flow_ref": flow_id,
        "description": if reverse {
            "ReaderEngagement is scanned; the wallet's DeviceEngagement is the first logical BLE application message."
        } else {
            "DeviceEngagement is scanned; SessionEstablishment is the first logical BLE application message."
        },
        "transport_and_crypto_stages_verified": true,
        "swiss_profile_authentication_fully_exercised": false,
        "steps": steps,
    })
}

fn engagement_semantic_payload(
    model: &str,
    public_key: &[u8],
    transfer_methods_present: bool,
) -> JsonValue {
    let reverse_reader = model == "ReaderEngagement";
    let mut payload = json!({
        "model": model,
        "version": "1.1",
        "cipher_suite": 1,
        "public_key_sec1_hex": hex(public_key),
        "dc_api_protocols": ["openid4vp-v1-signed"],
    });
    if transfer_methods_present {
        payload["ble_options"] = if reverse_reader {
            json!({
                "mode_selection": "documentation fixture choice; an implementation may advertise the inverse arrangement",
                "peripheral_server_mode_supported": false,
                "central_client_mode_supported": true,
                "central_client_uuid_hex": hex(&central_uuid()),
            })
        } else {
            json!({
                "mode_selection": "documentation fixture choice; an implementation may advertise the inverse arrangement",
                "peripheral_server_mode_supported": true,
                "central_client_mode_supported": false,
                "peripheral_server_uuid_hex": hex(&peripheral_uuid()),
            })
        };
    } else {
        payload["transfer_methods_present"] = JsonValue::Bool(false);
    }
    payload
}

fn message_verification_step(
    flow_id: &str,
    step_number: usize,
    step_id: &str,
    name: &str,
    model: &str,
    plaintext: &[u8],
    expected_ciphertext: &[u8],
    envelope: &Value,
    key: &[u8],
    role: Role,
) -> JsonValue {
    let counter = 1u32;
    let identifier: &[u8] = match role {
        Role::SkReader => &[0, 0, 0, 0, 0, 0, 0, 0],
        Role::SkDevice => &[0, 0, 0, 0, 0, 0, 0, 1],
    };
    let mut iv = identifier.to_vec();
    iv.extend_from_slice(&counter.to_be_bytes());
    let input_json: JsonValue = serde_json::from_slice(plaintext)
        .unwrap_or_else(|error| panic!("{flow_id}.{step_id}: payload is valid JSON: {error}"));
    let encrypted = encrypt_epoch_iso_180135(plaintext, key, role, counter)
        .expect("documentation session key encrypts payload");
    assert_eq!(
        encrypted, expected_ciphertext,
        "{flow_id}.{step_id}: encryption vector matches"
    );
    let decoded_envelope_bytes = cbor(envelope);
    let decoded_envelope = decode_cbor(&decoded_envelope_bytes);
    assert_eq!(
        decoded_envelope, *envelope,
        "{flow_id}.{step_id}: envelope CBOR round trips"
    );
    let envelope_ciphertext = cbor_map_bytes(&decoded_envelope, "data")
        .unwrap_or_else(|| panic!("{flow_id}.{step_id}: decoded envelope contains data bstr"));
    assert_eq!(envelope_ciphertext, expected_ciphertext);
    let decrypted = decrypt_epoch_iso_180135(envelope_ciphertext, key, role, counter)
        .unwrap_or_else(|| panic!("{flow_id}.{step_id}: AES-GCM decryption succeeds"));
    assert_eq!(
        decrypted, plaintext,
        "{flow_id}.{step_id}: decryption recovers payload bytes"
    );
    let decoded_json: JsonValue = serde_json::from_slice(&decrypted)
        .unwrap_or_else(|error| panic!("{flow_id}.{step_id}: decrypted JSON decodes: {error}"));
    assert_eq!(
        decoded_json, input_json,
        "{flow_id}.{step_id}: JSON decode matches source payload"
    );
    if model == "SessionData" {
        assert_eq!(
            cbor_map_bytes(&decoded_envelope, "shaSum"),
            Some(Sha256::digest(expected_ciphertext).as_slice()),
            "{flow_id}.{step_id}: Swiss/debug shaSum matches ciphertext",
        );
    }

    json!({
        "id": format!("{flow_id}.{step_id}"),
        "example_ref": match (flow_id, model) {
            ("reverse_flow", "SessionEstablishment") => "encoded_request_reverse",
            ("reverse_flow", _) => "encoded_response_reverse",
            (_, "SessionEstablishment") => "encoded_request",
            _ => "encoded_response",
        },
        "source_refs": if model == "SessionEstablishment" {
            ["kotlin_reader_request_encryption", "kotlin_session_establishment_cbor", "rust_iso_aes_gcm_encrypt", "kotlin_wallet_request_decryption", "kotlin_doc_test_flow_round_trip"]
        } else {
            ["kotlin_wallet_submit_response", "kotlin_session_data_cbor", "rust_iso_aes_gcm_encrypt", "kotlin_verifier_reverse_and_response", "kotlin_doc_test_flow_round_trip"]
        },
        "step": step_number,
        "name": name,
        "direction": if model == "SessionEstablishment" { "reader -> wallet" } else { "wallet -> reader" },
        "stages": [
            {
                "stage": "payload",
                "format": "DC API JSON",
                "value": input_json,
                "utf8": String::from_utf8_lossy(plaintext),
                "utf8_hex": hex(plaintext),
            },
            {
                "stage": "encryption",
                "algorithm": "AES-256-GCM / ISO 18013-5",
                "key_role": if role == Role::SkReader { "SKReader" } else { "SKDevice" },
                "key_hex": hex(key),
                "counter": counter,
                "epoch": counter,
                "identifier_hex": hex(identifier),
                "iv_hex": hex(&iv),
                "input_utf8_hex": hex(plaintext),
                "ciphertext_and_tag_hex": hex(expected_ciphertext),
                "decryption_recovers_exact_input": true,
            },
            {
                "stage": "CBOR encoding",
                "model": model,
                "cbor_hex": hex(&decoded_envelope_bytes),
                "base64url_without_padding": URL_SAFE_NO_PAD.encode(&decoded_envelope_bytes),
                "encoded_data_field_hex": hex(expected_ciphertext),
                "CBOR_round_trip_verified": true,
            },
            {
                "stage": "CBOR decoding",
                "model": model,
                "decoded_data_field_hex": hex(envelope_ciphertext),
                "decoded_data_matches_ciphertext": true,
            },
            {
                "stage": "decryption",
                "algorithm": "AES-256-GCM / ISO 18013-5",
                "key_role": if role == Role::SkReader { "SKReader" } else { "SKDevice" },
                "counter": counter,
                "epoch": counter,
                "identifier_hex": hex(identifier),
                "iv_hex": hex(&iv),
                "input_ciphertext_hex": hex(envelope_ciphertext),
                "output_utf8": String::from_utf8(decrypted.clone()).expect("verified UTF-8"),
                "output_utf8_hex": hex(&decrypted),
                "decryption_verified": true,
            },
            {
                "stage": "JSON decoding",
                "decoded_value": decoded_json,
                "decoded_value_matches_original_payload": true,
            },
        ],
        "shaSum_verified": model == "SessionData",
    })
}

fn decode_cbor(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).expect("encoded sample is valid CBOR")
}

fn end_to_end_flow_payload(
    origin: &str,
    session_transcript_bytes: &[u8],
    reverse_origin: &str,
    reverse_session_transcript_bytes: &[u8],
) -> JsonValue {
    json!({
        "variants": {
            "reader_engagement": {
                "flow_ref": "reverse_flow",
                "steps": [
                {"example_ref": "reader_engagement", "action": "reader creates ReaderEngagement and advertises mdoc:<base64url(cbor)>"},
                {"example_ref": "reader_engagement", "action": "wallet scans ReaderEngagement and connects using the advertised BLE mode"},
                {"example_ref": "reverse_device_engagement", "action": "wallet sends DeviceEngagement without TransferMethods as the first application message"},
                {"example_ref": "encryption_reverse", "action": "reader parses the engagement, then both peers derive the reverse-flow SessionTranscript and session keys"},
                {"example_ref": "encoded_request_reverse", "action": "reader sends SessionEstablishment after deriving the session cipher"},
                {"example_ref": "encoded_response_reverse", "action": "wallet replies with encrypted SessionData"}
                ]
            },
            "device_engagement": {
                "flow_ref": "normal_flow",
                "steps": [
                {"example_ref": "device_engagement", "action": "wallet creates DeviceEngagement and advertises mdoc:<base64url(cbor)>"},
                {"example_ref": "device_engagement", "action": "reader scans DeviceEngagement and connects using the advertised BLE mode"}
                ]
            }
        },
        "common_steps": [
            {"step": 1, "example_ref": "encryption", "actor": "reader and wallet", "action": "normal-flow transcript and keys: DeviceEngagement, eReaderKey, and handover"},
            {"step": 2, "example_ref": "encryption_reverse", "actor": "reader and wallet", "action": "reverse-flow transcript and keys: reverse DeviceEngagement, eReaderKey, and handover"},
            {"step": 3, "example_ref": "encoded_request", "actor": "reader", "action": "create a signed OpenID4VP request, wrap it in the DC API envelope, encrypt it, and send SessionEstablishment"},
            {"step": 4, "example_ref": "encoded_request", "actor": "wallet", "action": "decrypt and parse the request; in the Swiss profile validate verifier attestations, verifier information, expected origin, and dc_api.jwt response mode before consent"},
            {"step": 5, "example_ref": "encoded_response", "actor": "wallet", "action": "obtain user consent, select documents, create the mdoc/SD-JWT presentation response, encrypt it, and send SessionData"},
            {"step": 6, "example_ref": "encoded_response", "actor": "reader", "action": "optionally validate the shaSum debug extension, decrypt SessionData, verify the OpenID4VP response, and finish the exchange"}
        ],
        "example_refs": ["reader_engagement", "device_engagement", "reverse_device_engagement", "encoded_request", "encoded_request_reverse", "encoded_response", "encoded_response_reverse", "encryption", "encryption_reverse"],
        "session_transcript_outer_hex": hex(session_transcript_bytes),
        "origin": origin,
        "reverse_session_transcript_outer_hex": hex(reverse_session_transcript_bytes),
        "reverse_origin": reverse_origin,
        "transport_boundary": "Proximity carries encrypted request/response bytes; Swiss verifier-attestation trust policy belongs to the Swiss OID4VP profile integration."
    })
}

fn openid4vp_request_claims(origin: &str) -> JsonValue {
    json!({
        "expected_origins": [origin],
        "client_id": "did:example:verifier",
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": "documentation-nonce",
        "verifier_info": ["<Swiss verifier information from the signed request>"],
        "verifier_attestations": ["<Swiss OID4VP verifier attestation(s)>"]
    })
}

fn cose_key_from_p256_public_key(public_key: &[u8]) -> Value {
    assert_eq!(
        public_key.len(),
        65,
        "P-256 uncompressed SEC1 key must be 65 bytes"
    );
    Value::Map(vec![
        (integer(1), integer(2)),
        (integer(-1), integer(1)),
        (integer(-2), Value::Bytes(public_key[1..33].to_vec())),
        (integer(-3), Value::Bytes(public_key[33..65].to_vec())),
    ])
}

fn engagement(cose_key: &Value, central_mode: bool, peripheral_mode: bool) -> Value {
    let cose_key_bytes = cbor(cose_key);
    let mut ble_options = vec![
        (integer(0), Value::Bool(peripheral_mode)),
        (integer(1), Value::Bool(central_mode)),
    ];
    if central_mode {
        ble_options.push((integer(11), Value::Bytes(central_uuid())));
    }
    if peripheral_mode {
        ble_options.push((integer(10), Value::Bytes(peripheral_uuid())));
    }
    Value::Map(vec![
        (integer(0), text("1.1")),
        (
            integer(1),
            Value::Array(vec![
                integer(1),
                Value::Tag(24, Box::new(Value::Bytes(cose_key_bytes))),
            ]),
        ),
        (
            integer(2),
            Value::Array(vec![Value::Array(vec![
                integer(2),
                integer(1),
                Value::Map(ble_options),
            ])]),
        ),
        (
            integer(6),
            Value::Map(vec![(
                integer(0x4443_7631),
                Value::Array(vec![text("openid4vp-v1-signed")]),
            )]),
        ),
    ])
}

fn engagement_without_transfer_methods(cose_key: &Value) -> Value {
    let mut value = engagement(cose_key, false, false);
    if let Value::Map(entries) = &mut value {
        entries.retain(|(key, _)| key != &integer(2));
    }
    value
}

fn central_uuid() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x00, 0x02, 0xa1, 0x23, 0x48, 0xce, 0x89, 0x6b, 0x4c, 0x76, 0x97, 0x33, 0x73,
        0xe6,
    ]
}

fn peripheral_uuid() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x00, 0x01, 0xa1, 0x23, 0x48, 0xce, 0x89, 0x6b, 0x4c, 0x76, 0x97, 0x33, 0x73,
        0xe6,
    ]
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("sample CBOR is serializable");
    bytes
}

fn integer(value: i64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn typst_models(models: &[Model]) -> String {
    let mut result = String::from("(\n");
    for model in models {
        result.push_str("  (\n");
        result.push_str(&format!("    id: {},\n", typst_string(model.id)));
        result.push_str(&format!("    name: {},\n", typst_string(model.name)));
        result.push_str(&format!(
            "    encoding: {},\n",
            typst_string(model.encoding)
        ));
        result.push_str("    fields: (\n");
        for field in &model.fields {
            result.push_str("      (\n");
            result.push_str(&format!("        name: {},\n", typst_string(field.name)));
            result.push_str(&format!(
                "        cbor_key: {},\n",
                typst_json_value(&field.cbor_key)
            ));
            result.push_str(&format!(
                "        wire_type: {},\n",
                typst_string(field.wire_type)
            ));
            result.push_str(&format!("        optional: {},\n", field.optional));
            result.push_str(&format!(
                "        description: {},\n",
                typst_string(field.description)
            ));
            result.push_str("      ),\n");
        }
        result.push_str("    ),\n    dependencies: ");
        result.push_str(&typst_string_tuple(&model.dependencies));
        result.push_str(&format!(
            ",\n    example_ref: {},\n    kotlin_example_ref: {},\n  ),\n",
            typst_string(model.example_ref),
            typst_string(model.kotlin_example_ref),
        ));
    }
    result.push(')');
    result
}

fn typst_model_bundles(bundles: &[ModelBundle]) -> String {
    let mut result = String::from("(\n");
    for bundle in bundles {
        result.push_str("  (\n");
        result.push_str(&format!("    id: {},\n", typst_string(bundle.id)));
        result.push_str(&format!("    title: {},\n", typst_string(bundle.title)));
        result.push_str("    model_ids: ");
        result.push_str(&typst_string_tuple(&bundle.model_ids));
        result.push_str(&format!(
            ",\n    example_ref: {},\n    kotlin_example_ref: {},\n  ),\n",
            typst_string(bundle.example_ref),
            typst_string(bundle.kotlin_example_ref),
        ));
    }
    result.push(')');
    result
}

fn typst_string_tuple(values: &[&str]) -> String {
    let mut result = String::from("(");
    for value in values {
        result.push_str(&typst_string(value));
        result.push_str(", ");
    }
    result.push(')');
    result
}

fn typst_examples(examples: &[ExampleRecord]) -> String {
    let mut result = String::from("(\n");
    for example in examples {
        result.push_str("  (\n");
        result.push_str(&format!("    id: {},\n", typst_string(example.id())));
        result.push_str(&format!("    name: {},\n", typst_string(example.name())));
        result.push_str(&format!(
            "    payload_json: {},\n",
            typst_string(&serde_json::to_string_pretty(example.payload()).expect("example JSON"),),
        ));
        result.push_str(&format!(
            "    payload_display_json: {},\n",
            typst_string(
                &serde_json::to_string_pretty(&display_json_value(example.payload()))
                    .expect("example display JSON"),
            ),
        ));
        result.push_str("    payload: ");
        result.push_str(&typst_json_structure(example.payload()));
        result.push_str(",\n    verification_steps: ");
        result.push_str(&typst_verification_steps(example.payload()));
        result.push_str(",\n");
        result.push_str("  ),\n");
    }
    result.push(')');
    result
}

fn typst_verification_steps(payload: &JsonValue) -> String {
    let Some(steps) = payload
        .get("verification_trace")
        .and_then(|trace| trace.get("steps"))
        .and_then(JsonValue::as_array)
    else {
        return "()".to_owned();
    };
    let mut result = String::from("(\n");
    for step in steps {
        let id = step.get("id").and_then(JsonValue::as_str).unwrap_or("step");
        let name = step
            .get("name")
            .and_then(JsonValue::as_str)
            .unwrap_or("Flow step");
        let example_ref = step
            .get("example_ref")
            .and_then(JsonValue::as_str)
            .unwrap_or("encryption");
        result.push_str("      (\n");
        result.push_str(&format!("        id: {},\n", typst_string(id)));
        result.push_str(&format!("        name: {},\n", typst_string(name)));
        result.push_str(&format!(
            "        example_ref: {},\n",
            typst_string(example_ref)
        ));
        let source_refs = step
            .get("source_refs")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .filter_map(JsonValue::as_str)
            .collect::<Vec<_>>();
        result.push_str("        source_refs: ");
        result.push_str(&typst_string_tuple(&source_refs));
        result.push_str(",\n");
        result.push_str(&format!(
            "        payload_display_json: {},\n",
            typst_string(
                &serde_json::to_string_pretty(&display_json_value(step))
                    .expect("verification step JSON is serializable"),
            ),
        ));
        result.push_str("      ),\n");
    }
    result.push_str("    )");
    result
}

fn typst_json_structure(value: &JsonValue) -> String {
    match value {
        JsonValue::Object(fields) => {
            let mut result = String::from("(\n");
            for (key, value) in fields {
                result.push_str("      ");
                result.push_str(&typst_string(key));
                result.push_str(": ");
                result.push_str(&typst_json_structure(value));
                result.push_str(",\n");
            }
            result.push_str("    )");
            result
        }
        JsonValue::Array(items) => {
            let mut result = String::from("(");
            for item in items {
                result.push_str(&typst_json_structure(item));
                result.push_str(", ");
            }
            result.push(')');
            result
        }
        JsonValue::String(value) => typst_string(value),
        JsonValue::Number(value) => value.to_string(),
        JsonValue::Bool(value) => value.to_string(),
        JsonValue::Null => "none".to_owned(),
    }
}

fn typst_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => typst_string(value),
        JsonValue::Number(value) => value.to_string(),
        JsonValue::Bool(value) => value.to_string(),
        _ => typst_string(&value.to_string()),
    }
}

fn typst_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn flow_typst() -> &'static str {
    r#"#let proximity_flow = (
  (variant: "reader-engagement", flow_ref: "reverse_flow", example_refs: ("reader_engagement", "reverse_device_engagement", "encoded_request_reverse", "encoded_response_reverse", "encryption_reverse"), steps: (
    (step: 1, example_ref: "reader_engagement", trace_ref: "reverse_flow.engagement_qr", actor: "reader", sender: "reader", receiver: "wallet", action: "Scan ReaderEngagement QR"),
    (step: 2, example_ref: "reverse_device_engagement", trace_ref: "reverse_flow.device_engagement_first_message", actor: "wallet", sender: "wallet", receiver: "reader", action: "DeviceEngagement without TransferMethods as first application message"),
    (step: 3, example_ref: "encryption_reverse", trace_ref: "reverse_flow.session_transcript_and_keys", actor: "reader and wallet", local_actors: ("wallet", "reader"), line_style: "dashed", action: "SessionTranscript + ECDH; derive SKReader / SKDevice"),
    (step: 4, example_ref: "encoded_request_reverse", trace_ref: "reverse_flow.reader_request", actor: "reader", sender: "reader", receiver: "wallet", action: "SessionEstablishment: encrypted request + eReaderKey"),
    (step: 5, example_ref: "encoded_request_reverse", trace_ref: "reverse_flow.swiss_reader_authentication", actor: "wallet", local_actors: ("wallet",), line_style: "dashed", action: "Validate Reader Authentication; Obtain Consent"),
    (step: 6, example_ref: "encoded_response_reverse", trace_ref: "reverse_flow.wallet_response", actor: "wallet", sender: "wallet", receiver: "reader", action: "SessionData: Encrypted Wallet Response"),
  )),
  (variant: "device-engagement", flow_ref: "normal_flow", example_refs: ("device_engagement", "encoded_request", "encoded_response", "encryption"), steps: (
    (step: 1, example_ref: "device_engagement", trace_ref: "normal_flow.engagement_qr", actor: "wallet", sender: "wallet", receiver: "reader", action: "Scan DeviceEngagement QR"),
    (step: 2, example_ref: "device_engagement", trace_ref: "normal_flow.ble_connection", actor: "reader", sender: "reader", receiver: "wallet", action: "Scan DeviceEngagement; connect and signal readiness"),
    (step: 3, example_ref: "encryption", trace_ref: "normal_flow.session_transcript_and_keys", actor: "reader and wallet", local_actors: ("wallet", "reader"), line_style: "dashed", action: "SessionTranscript + ECDH; derive SKReader / SKDevice"),
    (step: 4, example_ref: "encoded_request", trace_ref: "normal_flow.reader_request", actor: "reader", sender: "reader", receiver: "wallet", action: "SessionEstablishment: encrypted request + eReaderKey"),
    (step: 5, example_ref: "encoded_request", trace_ref: "normal_flow.swiss_reader_authentication", actor: "wallet", local_actors: ("wallet",), line_style: "dashed", action: "Validate Reader Authentication; Obtain Consent"),
    (step: 6, example_ref: "encoded_response", trace_ref: "normal_flow.wallet_response", actor: "wallet", sender: "wallet", receiver: "reader", action: "SessionData: Encrypted Wallet Response"),
  )),
  (variant: "common-verification", example_refs: ("encryption", "encoded_request", "encoded_response"), steps: (
    (step: 1, example_ref: "encryption", actor: "reader and wallet", local_actors: ("wallet", "reader"), line_style: "dashed", action: "ECDH + ISO 18013-5 HKDF derive SKReader / SKDevice"),
    (step: 2, example_ref: "encoded_request", actor: "reader", sender: "reader", receiver: "wallet", action: "Signed OpenID4VP request in encrypted SessionEstablishment"),
    (step: 3, example_ref: "encoded_request", actor: "wallet", local_actors: ("wallet",), line_style: "dashed", action: "Swiss verifier attestations, origin, verifier info, dc_api.jwt, consent"),
    (step: 4, example_ref: "encoded_response", actor: "wallet", sender: "wallet", receiver: "reader", action: "Encrypted mdoc / SD-JWT response in SessionData"),
    (step: 5, example_ref: "encoded_response", actor: "reader", local_actors: ("reader",), line_style: "dashed", action: "shaSum, decrypt, verify OpenID4VP response, finish"),
  )),
)
"#
}

fn validate_typst_document(
    document_source: &str,
    data_source: &str,
    graph_source: &str,
    text_source: &str,
    code_source: &str,
) {
    let files = HashMap::from([
        (
            "proximity-data.typ".to_owned(),
            data_source.as_bytes().to_vec(),
        ),
        (
            "proximity-flow-graph.typ".to_owned(),
            graph_source.as_bytes().to_vec(),
        ),
        (
            "proximity-text.typ".to_owned(),
            text_source.as_bytes().to_vec(),
        ),
        (
            "proximity-code.typ".to_owned(),
            code_source.as_bytes().to_vec(),
        ),
        (
            "session_encryption.typ".to_owned(),
            include_bytes!("../session_encryption.typ").to_vec(),
        ),
        (
            "diag-notation.typ".to_owned(),
            include_bytes!("../diag-notation.typ").to_vec(),
        ),
        (
            "diag-notation.sublime-syntax".to_owned(),
            include_bytes!("../diag-notation.sublime-syntax").to_vec(),
        ),
    ]);
    validate_typst_with_files(document_source, files);
}

fn validate_typst_with_files(source: &str, files: HashMap<String, Vec<u8>>) {
    let world = kapun_pdf_rust::TypstWrapperWorld::new(".", source, files);
    let compiled = typst::compile::<typst::layout::PagedDocument>(&world);
    if let Err(errors) = compiled.output {
        eprintln!("generated proximity Typst did not compile:");
        for error in errors {
            eprintln!("{error:?}");
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod documentation_tests {
    use super::*;

    #[test]
    fn display_comments_keep_source_line_numbers_and_executable_code() {
        let source = concat!(
            "fn sample() {\n",
            "    // TODO remove this note\n",
            "    let a = \"https://example.test/TODO\"; // TODO later\n",
            "    /* TODO outer\n",
            "       /* nested */ comment */ let b = 7;\n",
            "    TODO(\"unimplemented branch\");\n",
            "    // Keep this explanation\n",
            "}\n",
        );
        let cleaned = strip_todo_comments(source);
        assert_eq!(source.lines().count(), cleaned.lines().count());
        assert!(cleaned.contains("\"https://example.test/TODO\""));
        assert!(cleaned.contains("TODO(\"unimplemented branch\")"));
        assert!(cleaned.contains("// Keep this explanation"));
        assert!(!cleaned.contains("TODO outer"));
        assert!(!cleaned.contains("TODO later"));
        let (_, start, end, focus) =
            extract_focused_excerpt(&cleaned, "fn sample", "let b = 7;", 1).unwrap();
        assert_eq!((start, end, focus), (4, 6, 5));
    }

    #[test]
    fn display_comments_respect_raw_and_multiline_strings() {
        let source = "let a = r##\"/* TODO literal */\"##;\nval b = \"\"\"// TODO literal\"\"\"\n// TODO remove";
        let cleaned = strip_todo_comments(source);
        assert_eq!(cleaned.lines().next(), source.lines().next());
        assert_eq!(cleaned.lines().nth(1), source.lines().nth(1));
        assert!(cleaned.lines().nth(2).unwrap().trim().is_empty());
    }

    #[test]
    fn reverse_flow_fixture_omits_transfer_methods_and_uses_its_own_crypto_vectors() {
        let examples = examples();
        let by_id = |id: &str| {
            examples
                .iter()
                .find(|example| example.id == id)
                .unwrap_or_else(|| panic!("missing fixture {id}"))
        };
        let decode_engagement = |id: &str| {
            let bytes = decode_hex(
                by_id(id)
                    .payload
                    .get("cbor_hex")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_else(|| panic!("{id} must contain CBOR hex")),
            )
            .unwrap_or_else(|error| panic!("{id} CBOR hex: {error}"));
            decode_cbor(&bytes)
        };

        assert!(cbor_map_has_integer_key(
            &decode_engagement("device_engagement"),
            2
        ));
        assert!(!cbor_map_has_integer_key(
            &decode_engagement("reverse_device_engagement"),
            2,
        ));

        let reverse_flow = &by_id("reverse_flow").payload;
        assert_eq!(
            reverse_flow
                .get("after_ble_connection")
                .and_then(|after| after.get("first_application_message_cbor_hex")),
            by_id("reverse_device_engagement").payload.get("cbor_hex"),
            "reverse flow's first application bytes must be its referenced engagement fixture",
        );
        let refs = reverse_flow
            .get("example_refs")
            .and_then(JsonValue::as_array)
            .expect("reverse flow lists its payload references");
        for id in [
            "reader_engagement",
            "reverse_device_engagement",
            "encoded_request_reverse",
            "encryption_reverse",
            "encoded_response_reverse",
        ] {
            assert!(refs.iter().any(|reference| reference == id), "missing {id}");
            assert!(examples.iter().any(|example| example.id == id));
        }
        let trace_steps = reverse_flow
            .get("verification_trace")
            .and_then(|trace| trace.get("steps"))
            .and_then(JsonValue::as_array)
            .expect("reverse flow contains verification trace");
        assert_eq!(
            trace_steps[1]
                .get("example_ref")
                .and_then(JsonValue::as_str),
            Some("reverse_device_engagement"),
        );
        assert_eq!(
            trace_steps[3]
                .get("example_ref")
                .and_then(JsonValue::as_str),
            Some("encoded_request_reverse"),
        );
        assert_eq!(
            trace_steps[5]
                .get("example_ref")
                .and_then(JsonValue::as_str),
            Some("encoded_response_reverse"),
        );
    }
}
