/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */
use std::{
    collections::HashMap,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use typst::{
    diag::{FileError, FileResult, PackageError, PackageResult, Severity, SourceDiagnostic},
    ecow::eco_format,
    foundations::{Bytes, Datetime},
    layout::PagedDocument,
    syntax::{package::PackageSpec, FileId, Source, VirtualPath},
    text::{Font, FontBook},
    utils::LazyHash,
    Library, LibraryExt, World, WorldExt,
};
use typst_pdf::PdfOptions;

/// A compiler diagnostic with a source location when Typst can provide one.
#[derive(uniffi::Record)]
pub struct TypstDiagnostic {
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub hints: Vec<String>,
}

/// The output and diagnostics from a Typst compile or render operation.
#[derive(uniffi::Record)]
pub struct TypstRenderResult {
    pub succeeded: bool,
    pub output: Vec<u8>,
    pub diagnostics: Vec<TypstDiagnostic>,
}

#[uniffi::export]
fn render(main_file: &str, additional_files: HashMap<String, Vec<u8>>) -> Vec<u8> {
    render_pdf_with_diagnostics(main_file, additional_files).output
}

/// Compiles a Typst document to PDF and returns compiler diagnostics to the caller.
#[uniffi::export]
fn render_with_diagnostics(
    main_file: &str,
    additional_files: HashMap<String, Vec<u8>>,
) -> TypstRenderResult {
    render_pdf_with_diagnostics(main_file, additional_files)
}

/// Compiles a Typst document and renders only its first page directly to PNG.
#[uniffi::export]
fn preview_png(main_file: &str, additional_files: HashMap<String, Vec<u8>>) -> TypstRenderResult {
    let world = TypstWrapperWorld::new(".", main_file, additional_files);
    let compiled = typst::compile(&world);
    let mut diagnostics = font_diagnostics(&world.font_errors);
    diagnostics.extend(to_diagnostics(&world, compiled.warnings.iter()));
    let document: PagedDocument = match compiled.output {
        Ok(document) => document,
        Err(errors) => {
            diagnostics.extend(to_diagnostics(&world, errors.iter()));
            return failed_result(diagnostics);
        }
    };

    let Some(page) = document.pages.first() else {
        diagnostics.push(TypstDiagnostic {
            severity: "Error".to_string(),
            message: "Typst produced a document with no pages".to_string(),
            file: String::new(),
            line: None,
            column: None,
            hints: vec![],
        });
        return failed_result(diagnostics);
    };

    // At 1.5 pixels per point, an A4 preview is about 900 pixels wide. This is
    // sufficient for the editor preview while keeping rasterization bounded.
    let pixmap = typst_render::render(page, 1.5);
    match pixmap.encode_png() {
        Ok(png) => TypstRenderResult {
            succeeded: true,
            output: png,
            diagnostics,
        },
        Err(error) => {
            diagnostics.push(TypstDiagnostic {
                severity: "Error".to_string(),
                message: format!("Could not encode Typst preview as PNG: {error}"),
                file: String::new(),
                line: None,
                column: None,
                hints: vec![],
            });
            failed_result(diagnostics)
        }
    }
}

fn render_pdf_with_diagnostics(
    main_file: &str,
    additional_files: HashMap<String, Vec<u8>>,
) -> TypstRenderResult {
    let world = TypstWrapperWorld::new(".", main_file, additional_files);
    let compiled = typst::compile(&world);
    let mut diagnostics = font_diagnostics(&world.font_errors);
    diagnostics.extend(to_diagnostics(&world, compiled.warnings.iter()));
    let document = match compiled.output {
        Ok(document) => document,
        Err(errors) => {
            diagnostics.extend(to_diagnostics(&world, errors.iter()));
            return failed_result(diagnostics);
        }
    };

    match typst_pdf::pdf(&document, &PdfOptions::default()) {
        Ok(pdf) => TypstRenderResult {
            succeeded: true,
            output: pdf,
            diagnostics,
        },
        Err(errors) => {
            diagnostics.extend(to_diagnostics(&world, errors.iter()));
            failed_result(diagnostics)
        }
    }
}

fn failed_result(diagnostics: Vec<TypstDiagnostic>) -> TypstRenderResult {
    TypstRenderResult {
        succeeded: false,
        output: vec![],
        diagnostics,
    }
}

fn font_diagnostics(font_errors: &[(String, String)]) -> Vec<TypstDiagnostic> {
    font_errors
        .iter()
        .map(|(file, message)| TypstDiagnostic {
            severity: "Warning".to_string(),
            message: message.clone(),
            file: file.clone(),
            line: None,
            column: None,
            hints: vec![],
        })
        .collect()
}

fn to_diagnostics<'a>(
    world: &TypstWrapperWorld,
    diagnostics: impl Iterator<Item = &'a SourceDiagnostic>,
) -> Vec<TypstDiagnostic> {
    diagnostics
        .map(|diagnostic| {
            let location = diagnostic.span.id().and_then(|file_id| {
                let source = world.source(file_id).ok()?;
                let range = world.range(diagnostic.span)?;
                let (line, column) = source.lines().byte_to_line_column(range.start)?;
                Some((
                    file_id
                        .vpath()
                        .as_rootless_path()
                        .display()
                        .to_string(),
                    u32::try_from(line + 1).ok()?,
                    u32::try_from(column + 1).ok()?,
                ))
            });

            TypstDiagnostic {
                severity: match diagnostic.severity {
                    Severity::Error => "Error".to_string(),
                    Severity::Warning => "Warning".to_string(),
                },
                message: diagnostic.message.to_string(),
                file: location
                    .as_ref()
                    .map(|(file, _, _)| file.clone())
                    .unwrap_or_default(),
                line: location.as_ref().map(|(_, line, _)| *line),
                column: location.as_ref().map(|(_, _, column)| *column),
                hints: diagnostic.hints.iter().map(ToString::to_string).collect(),
            }
        })
        .collect()
}

/// Main interface that determines the environment for Typst.
pub struct TypstWrapperWorld {
    /// Root path to which files will be resolved.
    root: PathBuf,

    /// The content of a source.
    source: Source,

    /// The standard library.
    library: LazyHash<Library>,

    /// Metadata about all known fonts.
    book: LazyHash<FontBook>,

    /// Metadata about all known fonts.
    fonts: Vec<Font>,

    /// Invalid font files bundled by the template, reported as warnings after compilation.
    font_errors: Vec<(String, String)>,

    /// Map of all known files.
    files: Arc<Mutex<HashMap<FileId, FileEntry>>>,

    /// Cache directory (e.g. where packages are downloaded to).
    cache_directory: PathBuf,

    /// http agent to download packages.
    http: ureq::Agent,

    /// Datetime.
    time: time::OffsetDateTime,
}

impl TypstWrapperWorld {
    pub fn new(root: &str, source: &str, additional_files: HashMap<String, Vec<u8>>) -> Self {
        let root = PathBuf::from(root);
        let (font_book, fonts, font_errors) = load_fonts(&additional_files);
        let mut files = HashMap::new();
        for (name, content) in additional_files {
            files.insert(
                FileId::new(None, VirtualPath::new(name)),
                FileEntry::new(content, None),
            );
        }

        let mut config = ureq::Agent::config_builder();
        if let Some(user_agent) = kapun_util_rust::network::user_agent() {
            config = config.user_agent(user_agent);
        }
        if kapun_util_rust::network::untrusted_tls_allowed() {
            config = config.tls_config(
                ureq::tls::TlsConfig::builder()
                    .disable_verification(true)
                    .build(),
            );
        }
        let http = ureq::Agent::new_with_config(config.build());

        Self {
            library: LazyHash::new(Library::default()),
            book: LazyHash::new(font_book),
            root,
            fonts,
            font_errors,
            source: Source::detached(source),
            time: time::OffsetDateTime::now_utc(),
            cache_directory: std::env::var_os("CACHE_DIRECTORY")
                .map(|os_path| os_path.into())
                .unwrap_or(std::env::temp_dir()),
            http,
            files: Arc::new(Mutex::new(files)),
        }
    }
}

/// A File that will be stored in the HashMap.
#[derive(Clone, Debug)]
struct FileEntry {
    bytes: Bytes,
    source: Option<Source>,
}

impl FileEntry {
    fn new(bytes: Vec<u8>, source: Option<Source>) -> Self {
        Self {
            bytes: Bytes::new(bytes),
            source,
        }
    }

    fn source(&mut self, id: FileId) -> FileResult<Source> {
        let source = if let Some(source) = &self.source {
            source
        } else {
            let contents = std::str::from_utf8(&self.bytes).map_err(|_| FileError::InvalidUtf8)?;
            let contents = contents.trim_start_matches('\u{feff}');
            let source = Source::new(id, contents.into());
            self.source.insert(source)
        };
        Ok(source.clone())
    }
}

impl TypstWrapperWorld {
    /// Helper to handle file requests.
    ///
    /// Requests will be either in packages or a local file.
    fn file(&self, id: FileId) -> FileResult<FileEntry> {
        let mut files = self.files.lock().map_err(|_| FileError::AccessDenied)?;
        if let Some(entry) = files.get(&id) {
            return Ok(entry.clone());
        }
        let path = if let Some(package) = id.package() {
            // Fetching file from package
            let package_dir = self.download_package(package)?;
            id.vpath().resolve(&package_dir)
        } else {
            // Fetching file from disk
            id.vpath().resolve(&self.root)
        }
        .ok_or(FileError::AccessDenied)?;

        let content = std::fs::read(&path).map_err(|error| FileError::from_io(error, &path))?;
        Ok(files
            .entry(id)
            .or_insert(FileEntry::new(content, None))
            .clone())
    }

    /// Downloads the package and returns the system path of the unpacked package.
    fn download_package(&self, package: &PackageSpec) -> PackageResult<PathBuf> {
        let package_subdir = format!("{}/{}/{}", package.namespace, package.name, package.version);
        let path = self.cache_directory.join(package_subdir);

        if path.exists() {
            return Ok(path);
        }

        eprintln!("downloading {package}");
        let url = format!(
            "https://packages.typst.org/{}/{}-{}.tar.gz",
            package.namespace, package.name, package.version,
        );

        let response = retry(|| {
            let response = self
                .http
                .get(&url)
                .call()
                .map_err(|error| eco_format!("{error}"))?;

            let status = response.status();
            if !status.is_success() {
                return Err(eco_format!(
                    "response returned unsuccessful status code {status}",
                ));
            }

            Ok(response)
        })
        .map_err(|error| PackageError::NetworkFailed(Some(error)))?;

        let mut compressed_archive = Vec::new();
        response
            .into_body()
            .into_reader()
            .read_to_end(&mut compressed_archive)
            .map_err(|error| PackageError::NetworkFailed(Some(eco_format!("{error}"))))?;
        let raw_archive = zune_inflate::DeflateDecoder::new(&compressed_archive)
            .decode_gzip()
            .map_err(|error| PackageError::MalformedArchive(Some(eco_format!("{error}"))))?;
        let mut archive = tar::Archive::new(raw_archive.as_slice());
        archive.unpack(&path).map_err(|error| {
            _ = std::fs::remove_dir_all(&path);
            PackageError::MalformedArchive(Some(eco_format!("{error}")))
        })?;

        Ok(path)
    }
}

/// This is the interface we have to implement such that `typst` can compile it.
///
/// I have tried to keep it as minimal as possible
impl typst::World for TypstWrapperWorld {
    /// Standard library.
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    /// Metadata about all known Books.
    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }

    /// Accessing the main source file.
    fn main(&self) -> FileId {
        self.source.id()
    }

    /// Accessing a specified source file (based on `FileId`).
    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.source.id() {
            Ok(self.source.clone())
        } else {
            self.file(id)?.source(id)
        }
    }

    /// Accessing a specified file (non-file).
    fn file(&self, id: FileId) -> FileResult<Bytes> {
        self.file(id).map(|file| file.bytes.clone())
    }

    /// Accessing a specified font per index of font book.
    fn font(&self, id: usize) -> Option<Font> {
        self.fonts.get(id).cloned()
    }

    /// Get the current date.
    ///
    /// Optionally, an offset in hours is given.
    fn today(&self, offset: Option<i64>) -> Option<Datetime> {
        let offset = offset.unwrap_or(0);
        let offset = time::UtcOffset::from_hms(offset.try_into().ok()?, 0, 0).ok()?;
        let time = self.time.checked_to_offset(offset)?;
        Some(Datetime::Date(time.date()))
    }
}

/// Helper function
fn fonts() -> Vec<Font> {
    typst_assets::fonts()
        .map(|entry| {
            let buffer = Bytes::new(entry);
            let face_count = ttf_parser::fonts_in_collection(&buffer).unwrap_or(1);

            (0..face_count)
                .map(move |face| {
                    Font::new(buffer.clone(), face).unwrap_or_else(|| {
                        panic!("failed to load font from embedded assets (face index {face})")
                    })
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect()
}

pub fn load_fonts(
    additional_files: &HashMap<String, Vec<u8>>,
) -> (FontBook, Vec<Font>, Vec<(String, String)>) {
    let mut bundled_fonts = Vec::new();
    let mut font_errors = Vec::new();
    let mut font_files = additional_files
        .iter()
        .filter(|(path, _)| is_bundled_font_path(path))
        .collect::<Vec<_>>();
    font_files.sort_by(|(left, _), (right, _)| left.cmp(right));

    for (path, bytes) in font_files {
        let data = Bytes::new(bytes.clone());
        let parsed = Font::iter(data).collect::<Vec<_>>();
        if parsed.is_empty() {
            font_errors.push((
                path.clone(),
                "File is not a supported TrueType or OpenType font".to_string(),
            ));
        } else {
            bundled_fonts.extend(parsed);
        }
    }

    let mut fonts = bundled_fonts;
    fonts.extend(default_fonts());
    let book = FontBook::from_fonts(&fonts);
    (book, fonts, font_errors)
}

fn is_bundled_font_path(path: &str) -> bool {
    let Some(relative_path) = path.strip_prefix("fonts/") else {
        return false;
    };
    let path = PathBuf::from(relative_path);
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str());
    extension.is_some_and(|extension| {
        extension.eq_ignore_ascii_case("ttf")
            || extension.eq_ignore_ascii_case("otf")
            || extension.eq_ignore_ascii_case("ttc")
    })
}

fn default_fonts() -> Vec<Font> {
    let mut fonts = fonts();

    let mut db = fontdb::Database::new();
    db.load_system_fonts();

    for font_face in db.faces() {
        let path = match &font_face.source {
            fontdb::Source::File(path) | fontdb::Source::SharedFile(path, _) => path,
            // We never add binary sources to the database, so there
            // shouln't be any.
            fontdb::Source::Binary(_) => continue,
        };
        let font_data = std::fs::read(path).unwrap();
        if let Some(font) = Font::new(typst::foundations::Bytes::new(font_data), font_face.index) {
            fonts.push(font);
        } else {
            println!("{:?} not found", path);
        }
    }
    for data in typst_assets::fonts() {
        let buffer = typst::foundations::Bytes::new(data);
        for font in Font::iter(buffer) {
            fonts.push(font);
        }
    }
    fonts
}

fn retry<T, E>(mut f: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    if let Ok(ok) = f() {
        Ok(ok)
    } else {
        f()
    }
}

#[cfg(target_arch = "arm")]
#[used]
static _KEEP_EH_FRAME_STUBS: [unsafe extern "C" fn(); 2] = [
    kapun_util_rust::__register_frame,
    kapun_util_rust::__deregister_frame,
];

uniffi::setup_scaffolding!();
