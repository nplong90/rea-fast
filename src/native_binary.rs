use flate2::read::ZlibDecoder;
use object::{Object, ObjectSection, ObjectSymbol};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::{error::Error, fs, path::Path};

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryLayout {
    pub path: String,
    pub sha256: String,
    pub format: String,
    pub architecture: String,
    pub endianness: String,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub total_sections: usize,
    pub symbol_count: usize,
    pub imports: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GoBuildInfo {
    pub has_go_buildinfo: bool,
    pub go_version: Option<String>,
    pub main_module: Option<String>,
    pub raw_deps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RustBinaryInfo {
    pub has_rust_auditable: bool,
    pub raw_json: Option<serde_json::Value>,
    pub rustc_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmSection {
    pub id: u8,
    pub name: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmInterface {
    pub is_wasm: bool,
    pub version: u32,
    pub sections: Vec<WasmSection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}

const MAX_NATIVE_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RUST_METADATA_BYTES: u64 = 16 * 1024 * 1024;

fn decompress_rust_metadata(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    (&mut decoder)
        .take(MAX_RUST_METADATA_BYTES + 1)
        .read_to_end(&mut decompressed)?;
    if decompressed.len() as u64 > MAX_RUST_METADATA_BYTES {
        return Err("Rust .dep-v0 section exceeds 16 MiB decompression limit".into());
    }
    Ok(decompressed)
}

fn read_bounded_artifact(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > MAX_NATIVE_ARTIFACT_BYTES {
        return Err("Native artifact exceeds 256 MiB input limit".into());
    }
    // A second bound protects against files growing while they are read.
    let mut bytes = Vec::new();
    file.take(MAX_NATIVE_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_NATIVE_ARTIFACT_BYTES {
        return Err("Native artifact grew beyond 256 MiB input limit".into());
    }
    Ok(bytes)
}

pub struct NativeInspector;

impl NativeInspector {
    pub fn inspect_layout(path: &Path) -> Result<BinaryLayout, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let obj_file = object::File::parse(&*bytes)?;

        let format = format!("{:?}", obj_file.format());
        let architecture = format!("{:?}", obj_file.architecture());
        let endianness = format!("{:?}", obj_file.endianness());
        let entry_point = obj_file.entry();

        let mut sections = Vec::new();
        for sec in obj_file.sections() {
            let name = sec.name().unwrap_or("").to_string();
            sections.push(SectionInfo {
                name,
                address: sec.address(),
                size: sec.size(),
            });
        }
        let total_sections = sections.len();

        let symbol_count = obj_file.symbols().count();

        let mut imports = Vec::new();
        if let Ok(imp_iter) = obj_file.imports() {
            for imp in imp_iter.flatten() {
                let name = match imp.name() {
                    object::NameOrOrdinal::Name(n) => String::from_utf8_lossy(n).to_string(),
                    object::NameOrOrdinal::Ordinal(ord) => format!("#{}", ord),
                };
                let lib = String::from_utf8_lossy(imp.library()).to_string();
                if lib.is_empty() {
                    imports.push(name);
                } else {
                    imports.push(format!("{}!{}", lib, name));
                }
            }
        }
        imports.sort();
        imports.dedup();

        Ok(BinaryLayout {
            path: path.to_string_lossy().to_string(),
            sha256,
            format,
            architecture,
            endianness,
            entry_point,
            sections,
            total_sections,
            symbol_count,
            imports,
        })
    }

    pub fn inspect_go(path: &Path) -> Result<GoBuildInfo, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        // Scan for Go buildinf signature: \xff Go buildinf:
        let magic = b"\xff Go buildinf:";
        let mut go_version = None;
        let mut main_module = None;
        let mut raw_deps = Vec::new();

        if let Some(pos) = bytes.windows(magic.len()).position(|w| w == magic) {
            let data = &bytes[pos..std::cmp::min(pos + 16 * 1024, bytes.len())];
            let text = String::from_utf8_lossy(data);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("go\t") || trimmed.starts_with("go1.") {
                    go_version = Some(trimmed.to_string());
                } else if trimmed.starts_with("mod\t") || trimmed.starts_with("path\t") {
                    main_module = Some(trimmed.to_string());
                } else if trimmed.starts_with("dep\t") {
                    raw_deps.push(trimmed.to_string());
                }
            }

            return Ok(GoBuildInfo {
                has_go_buildinfo: true,
                go_version,
                main_module,
                raw_deps,
            });
        }

        Ok(GoBuildInfo {
            has_go_buildinfo: false,
            go_version: None,
            main_module: None,
            raw_deps: Vec::new(),
        })
    }

    pub fn inspect_rust(path: &Path) -> Result<RustBinaryInfo, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        let mut rustc_commit = None;

        // Search for /rustc/<40-hex>/
        let text = String::from_utf8_lossy(&bytes);
        if let Some(pos) = text.find("/rustc/") {
            let sub = &text[pos + 7..];
            if sub.len() >= 40 {
                let candidate = &sub[..40];
                if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                    rustc_commit = Some(candidate.to_string());
                }
            }
        }

        if let Ok(obj_file) = object::File::parse(&*bytes) {
            for sec in obj_file.sections() {
                if sec.name().unwrap_or("") == ".dep-v0"
                    && let Ok(data) = sec.data()
                {
                    let decompressed = decompress_rust_metadata(data)?;
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decompressed) {
                        return Ok(RustBinaryInfo {
                            has_rust_auditable: true,
                            raw_json: Some(json),
                            rustc_commit,
                        });
                    }
                }
            }
        }

        Ok(RustBinaryInfo {
            has_rust_auditable: false,
            raw_json: None,
            rustc_commit,
        })
    }

    pub fn inspect_wasm(bytes: &[u8]) -> WasmInterface {
        if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
            return WasmInterface {
                is_wasm: false,
                version: 0,
                sections: Vec::new(),
                imports: Vec::new(),
                exports: Vec::new(),
            };
        }

        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([1, 0, 0, 0]));
        let mut sections = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();

        let mut offset = 8;
        while offset < bytes.len() {
            let id = bytes[offset];
            offset += 1;
            if offset >= bytes.len() {
                break;
            }

            // Read LEB128 length
            let (len, shift) = read_leb128(&bytes[offset..]);
            offset += shift;
            if offset + len > bytes.len() {
                break;
            }

            let sec_data = &bytes[offset..offset + len];
            let name = match id {
                0 => "custom",
                1 => "type",
                2 => "import",
                3 => "function",
                4 => "table",
                5 => "memory",
                6 => "global",
                7 => "export",
                8 => "start",
                9 => "element",
                10 => "code",
                11 => "data",
                12 => "data_count",
                _ => "unknown",
            }
            .to_string();

            if id == 7 {
                // Export section
                Self::parse_wasm_exports(sec_data, &mut exports);
            } else if id == 2 {
                // Import section
                Self::parse_wasm_imports(sec_data, &mut imports);
            }

            sections.push(WasmSection {
                id,
                name,
                size: len,
            });

            offset += len;
        }

        WasmInterface {
            is_wasm: true,
            version,
            sections,
            imports,
            exports,
        }
    }

    fn parse_wasm_exports(data: &[u8], exports: &mut Vec<String>) {
        if data.is_empty() {
            return;
        }
        let mut cur = 0;
        let (count, shift) = read_leb128(&data[cur..]);
        cur += shift;

        for _ in 0..count {
            if cur >= data.len() {
                break;
            }
            let (name_len, s) = read_leb128(&data[cur..]);
            cur += s;
            if cur + name_len > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[cur..cur + name_len]).to_string();
            cur += name_len;
            if cur < data.len() {
                cur += 1; // kind
                let (_, idx_shift) = read_leb128(&data[cur..]);
                cur += idx_shift;
            }
            exports.push(name);
        }
    }

    fn parse_wasm_imports(data: &[u8], imports: &mut Vec<String>) {
        if data.is_empty() {
            return;
        }
        let mut cur = 0;
        let (count, shift) = read_leb128(&data[cur..]);
        cur += shift;

        for _ in 0..count {
            if cur >= data.len() {
                break;
            }
            let (mod_len, s) = read_leb128(&data[cur..]);
            cur += s;
            if cur + mod_len > data.len() {
                break;
            }
            let mod_name = String::from_utf8_lossy(&data[cur..cur + mod_len]).to_string();
            cur += mod_len;

            if cur >= data.len() {
                break;
            }
            let (field_len, s2) = read_leb128(&data[cur..]);
            cur += s2;
            if cur + field_len > data.len() {
                break;
            }
            let field_name = String::from_utf8_lossy(&data[cur..cur + field_len]).to_string();
            cur += field_len;

            if cur < data.len() {
                let kind = data[cur];
                cur += 1;
                match kind {
                    0 | 1 => {
                        // func or table
                        let (_, idx_shift) = read_leb128(&data[cur..]);
                        cur += idx_shift;
                    }
                    2 => {
                        // memory
                        let (_, idx_shift) = read_leb128(&data[cur..]);
                        cur += idx_shift;
                    }
                    _ => {}
                }
            }
            imports.push(format!("{}.{}", mod_name, field_name));
        }
    }

    pub fn calculate_entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let total = bytes.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    pub fn inspect_byte_entropy(bytes: &[u8], chunk_size: usize) -> Value {
        let chunk_size = if chunk_size == 0 { 4096 } else { chunk_size };
        let overall_entropy = Self::calculate_entropy(bytes);
        // Keep the public number of chunks, but never materialize an
        // unbounded Vec<Value> when a caller chooses chunk_size = 1.
        let chunk_count = bytes.len().div_ceil(chunk_size);
        let mut chunk_entropies = Vec::with_capacity(chunk_count.min(64));
        for (i, chunk) in bytes.chunks(chunk_size).take(64).enumerate() {
            chunk_entropies.push(json!({
                "offset": i * chunk_size,
                "size": chunk.len(),
                "entropy": (Self::calculate_entropy(chunk) * 1000.0).round() / 1000.0,
            }));
        }
        let classification = if overall_entropy > 7.5 {
            "encrypted_or_high_entropy_compressed"
        } else if overall_entropy > 6.5 {
            "compressed_or_packed"
        } else if overall_entropy > 4.5 {
            "native_code_or_structured_binary"
        } else {
            "sparse_text_or_uncompressed_data"
        };

        json!({
            "total_bytes": bytes.len(),
            "overall_entropy": (overall_entropy * 1000.0).round() / 1000.0,
            "classification": classification,
            "chunk_count": chunk_count,
            "chunk_size": chunk_size,
            "chunks_truncated": chunk_count > 64,
            "chunks": chunk_entropies
        })
    }

    pub fn list_strings(bytes: &[u8], min_len: usize, limit: usize) -> Vec<String> {
        let min_len = if min_len == 0 { 4 } else { min_len };
        let limit = if limit == 0 { 200 } else { limit };
        let mut strings = Vec::new();
        let mut cur = Vec::new();

        for &b in bytes {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                cur.push(b);
            } else {
                if cur.len() >= min_len
                    && let Ok(s) = String::from_utf8(cur.clone())
                {
                    strings.push(s);
                    if strings.len() >= limit {
                        break;
                    }
                }
                cur.clear();
            }
        }
        if cur.len() >= min_len
            && strings.len() < limit
            && let Ok(s) = String::from_utf8(cur)
        {
            strings.push(s);
        }
        strings
    }

    pub fn list_sections(path: &Path) -> Result<Vec<SectionInfo>, Box<dyn Error>> {
        let layout = Self::inspect_layout(path)?;
        Ok(layout.sections)
    }

    pub fn list_symbols(path: &Path, limit: usize) -> Result<Vec<String>, Box<dyn Error>> {
        let limit = if limit == 0 { 200 } else { limit };
        let bytes = read_bounded_artifact(path)?;
        let obj = object::File::parse(&*bytes)?;
        let mut symbols = Vec::new();
        for sym in obj.symbols() {
            if let Ok(name) = sym.name()
                && !name.is_empty()
            {
                symbols.push(name.to_string());
                if symbols.len() >= limit {
                    break;
                }
            }
        }
        Ok(symbols)
    }

    pub fn inspect_native_exports(path: &Path) -> Result<Value, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        let obj = object::File::parse(&*bytes)?;
        let mut exports = Vec::new();
        if let Ok(exp_iter) = obj.exports() {
            for exp in exp_iter.flatten() {
                let name = match exp.name() {
                    object::NameOrOrdinal::Name(n) => String::from_utf8_lossy(n).to_string(),
                    object::NameOrOrdinal::Ordinal(ord) => format!("#{}", ord),
                };
                let address = match exp.target() {
                    object::ExportTarget::Address { address } => Some(address),
                    object::ExportTarget::Absolute { value } => Some(value),
                    _ => None,
                };
                exports.push(json!({
                    "name": name,
                    "address": address,
                }));
            }
        }
        Ok(json!({
            "path": path.to_string_lossy(),
            "total_exports": exports.len(),
            "exports": if exports.len() > 200 { &exports[..200] } else { &exports[..] },
        }))
    }

    pub fn inspect_macho(path: &Path) -> Result<Value, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let layout = Self::inspect_layout(path)?;
        let is_macho = layout.format.to_lowercase().contains("macho");

        Ok(json!({
            "path": path.to_string_lossy(),
            "sha256": sha256,
            "is_macho": is_macho,
            "format": layout.format,
            "architecture": layout.architecture,
            "endianness": layout.endianness,
            "entry_point": layout.entry_point,
            "section_count": layout.total_sections,
            "sections": layout.sections,
            "symbol_count": layout.symbol_count,
            "imports": layout.imports,
            "file_size": bytes.len(),
        }))
    }

    pub fn list_architectures(path: &Path) -> Result<Value, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        if bytes.len() >= 4 {
            let magic = &bytes[..4];
            if magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xbe, 0xba, 0xfe, 0xca] {
                let nfat_arch = if bytes.len() >= 8 {
                    u32::from_be_bytes(bytes[4..8].try_into().unwrap_or([0, 0, 0, 0])) as usize
                } else {
                    1
                };
                return Ok(json!({
                    "path": path.to_string_lossy(),
                    "is_universal": true,
                    "architecture_count": nfat_arch,
                    "architectures": ["arm64", "x86_64"],
                    "format": "Mach-O Universal Binary"
                }));
            }
        }
        let layout = Self::inspect_layout(path)?;
        Ok(json!({
            "path": path.to_string_lossy(),
            "is_universal": false,
            "architecture_count": 1,
            "architectures": [layout.architecture],
            "format": layout.format
        }))
    }

    pub fn compare_wasm_interfaces(left_bytes: &[u8], right_bytes: &[u8]) -> Value {
        let left = Self::inspect_wasm(left_bytes);
        let right = Self::inspect_wasm(right_bytes);

        let left_exp_set: std::collections::HashSet<_> = left.exports.iter().collect();
        let right_exp_set: std::collections::HashSet<_> = right.exports.iter().collect();
        let left_imp_set: std::collections::HashSet<_> = left.imports.iter().collect();
        let right_imp_set: std::collections::HashSet<_> = right.imports.iter().collect();

        let added_exports: Vec<_> = right_exp_set
            .difference(&left_exp_set)
            .copied()
            .cloned()
            .collect();
        let removed_exports: Vec<_> = left_exp_set
            .difference(&right_exp_set)
            .copied()
            .cloned()
            .collect();
        let added_imports: Vec<_> = right_imp_set
            .difference(&left_imp_set)
            .copied()
            .cloned()
            .collect();
        let removed_imports: Vec<_> = left_imp_set
            .difference(&right_imp_set)
            .copied()
            .cloned()
            .collect();

        json!({
            "left_wasm": left.is_wasm,
            "right_wasm": right.is_wasm,
            "left_version": left.version,
            "right_version": right.version,
            "added_exports": added_exports,
            "removed_exports": removed_exports,
            "added_imports": added_imports,
            "removed_imports": removed_imports,
            "left_sections": left.sections.len(),
            "right_sections": right.sections.len(),
            "is_identical": added_exports.is_empty() && removed_exports.is_empty() && added_imports.is_empty() && removed_imports.is_empty()
        })
    }

    pub fn inspect_il2cpp_metadata(path: &Path) -> Result<Value, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        if bytes.len() < 16 {
            return Err("File too small for IL2CPP metadata".into());
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into()?);
        if magic != 0xFAB11BAF {
            return Ok(json!({
                "is_il2cpp_metadata": false,
                "error": "Invalid IL2CPP magic signature (expected 0xFAB11BAF)"
            }));
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into()?);
        let string_literal_offset = if bytes.len() >= 12 {
            u32::from_le_bytes(bytes[8..12].try_into()?)
        } else {
            0
        };
        let string_literal_size = if bytes.len() >= 16 {
            u32::from_le_bytes(bytes[12..16].try_into()?)
        } else {
            0
        };
        let sha256 = format!("{:x}", Sha256::digest(&bytes));

        Ok(json!({
            "is_il2cpp_metadata": true,
            "path": path.to_string_lossy(),
            "sha256": sha256,
            "version": version,
            "file_size": bytes.len(),
            "string_literal_offset": string_literal_offset,
            "string_literal_size": string_literal_size,
        }))
    }

    pub fn inspect_artifact(path: &Path) -> Result<Value, Box<dyn Error>> {
        if path.is_dir() {
            let mut file_count = 0;
            let mut total_bytes = 0u64;
            for entry in ignore::WalkBuilder::new(path).build().flatten() {
                if let Ok(meta) = entry.metadata()
                    && meta.is_file()
                {
                    file_count += 1;
                    total_bytes += meta.len();
                }
            }
            return Ok(json!({
                "path": path.to_string_lossy(),
                "artifact_kind": "directory",
                "file_count": file_count,
                "total_bytes": total_bytes,
            }));
        }

        let bytes = read_bounded_artifact(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let path_str = path.to_string_lossy().to_string();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 1. ASAR
        if (ext == "asar" || (bytes.len() >= 16 && bytes[0..4] == [0x04, 0x00, 0x00, 0x00]))
            && let Ok(archive) = crate::asar::AsarArchive::open(path)
        {
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "chromium_asar_archive",
                "sha256": sha256,
                "total_entries": archive.entries.len(),
                "file_size": bytes.len(),
            }));
        }

        // 2. ZIP / APK
        if bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04" {
            if (ext == "apk" || ext == "jar")
                && let Ok(apk_info) = crate::mobile::MobileInspector::inspect_apk(path)
            {
                return Ok(json!({
                    "path": path_str,
                    "artifact_kind": "android_apk",
                    "sha256": sha256,
                    "package_name": apk_info.package_name,
                    "activities_count": apk_info.activities.len(),
                    "permissions_count": apk_info.permissions.len(),
                    "dex_count": apk_info.dex_files.len(),
                    "total_files": apk_info.total_files,
                }));
            }
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "zip_archive",
                "sha256": sha256,
                "file_size": bytes.len(),
            }));
        }

        // 3. SQLite
        if bytes.len() >= 16
            && &bytes[0..16] == b"SQLite format 3\0"
            && let Ok(db) = crate::storage_pcap::StoragePcapInspector::inspect_sqlite(path)
        {
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "sqlite_database",
                "sha256": sha256,
                "tables": db.tables,
                "page_size": db.page_size,
                "file_size": bytes.len(),
            }));
        }

        // 4. PCAP / PCAPNG
        if bytes.len() >= 4
            && (bytes[0..4] == [0xd4, 0xc3, 0xb2, 0xa1]
                || bytes[0..4] == [0xa1, 0xb2, 0xc3, 0xd4]
                || bytes[0..4] == [0x0a, 0x0d, 0x0d, 0x0a])
            && let Ok(pcap) = crate::storage_pcap::StoragePcapInspector::inspect_pcap(path)
        {
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "packet_capture",
                "sha256": sha256,
                "format": pcap.format,
                "total_packets": pcap.total_packets,
                "file_size": bytes.len(),
            }));
        }

        // 5. Plist
        if bytes.starts_with(b"bplist00") || (ext == "plist" && bytes.starts_with(b"<?xml")) {
            let plist_res = crate::plist::inspect_plist(&json!({ "path": path_str }));
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "property_list",
                "sha256": sha256,
                "detail": plist_res,
                "file_size": bytes.len(),
            }));
        }

        // 6. Unity IL2CPP global-metadata
        if bytes.len() >= 4
            && u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0; 4])) == 0xFAB11BAF
            && let Ok(meta) = Self::inspect_il2cpp_metadata(path)
        {
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "il2cpp_metadata",
                "detail": meta,
            }));
        }

        // 7. WebAssembly
        if bytes.len() >= 4 && &bytes[0..4] == b"\0asm" {
            let wasm = Self::inspect_wasm(&bytes);
            return Ok(json!({
                "path": path_str,
                "artifact_kind": "webassembly",
                "sha256": sha256,
                "version": wasm.version,
                "sections_count": wasm.sections.len(),
                "imports_count": wasm.imports.len(),
                "exports_count": wasm.exports.len(),
                "file_size": bytes.len(),
            }));
        }

        // 8. Native Executable (ELF, Mach-O, PE)
        if let Ok(layout) = Self::inspect_layout(path) {
            let is_dotnet = if ext == "dll" || ext == "exe" {
                crate::managed::inspect_managed_artifact(&json!({ "path": path_str }))["is_managed_cli"].as_bool().unwrap_or(false)
            } else {
                false
            };

            return Ok(json!({
                "path": path_str,
                "artifact_kind": if is_dotnet { "dotnet_assembly" } else { "native_binary" },
                "sha256": sha256,
                "format": layout.format,
                "architecture": layout.architecture,
                "sections_count": layout.total_sections,
                "symbols_count": layout.symbol_count,
                "file_size": bytes.len(),
            }));
        }

        // Fallback: general file
        let entropy = Self::calculate_entropy(&bytes);
        Ok(json!({
            "path": path_str,
            "artifact_kind": "file",
            "sha256": sha256,
            "file_size": bytes.len(),
            "entropy": (entropy * 1000.0).round() / 1000.0,
        }))
    }

    pub fn inspect_model_artifact(path: &Path) -> Result<Value, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let path_str = path.to_string_lossy().to_string();

        if bytes.len() >= 4 && &bytes[0..4] == b"GGUF" {
            let version = if bytes.len() >= 8 {
                u32::from_le_bytes(bytes[4..8].try_into()?)
            } else {
                0
            };
            let tensor_count = if bytes.len() >= 16 {
                u64::from_le_bytes(bytes[8..16].try_into()?)
            } else {
                0
            };
            let kv_count = if bytes.len() >= 24 {
                u64::from_le_bytes(bytes[16..24].try_into()?)
            } else {
                0
            };
            return Ok(json!({
                "path": path_str,
                "format": "GGUF",
                "version": version,
                "tensor_count": tensor_count,
                "metadata_kv_count": kv_count,
                "file_size": bytes.len(),
                "sha256": sha256,
            }));
        }

        if bytes.len() >= 8 {
            let header_len = u64::from_le_bytes(bytes[0..8].try_into()?) as usize;
            if header_len > 0
                && header_len < 100_000_000
                && 8 + header_len <= bytes.len()
                && let Ok(val) = serde_json::from_slice::<Value>(&bytes[8..8 + header_len])
            {
                let tensor_names: Vec<String> = if let Some(map) = val.as_object() {
                    map.keys()
                        .filter(|k| *k != "__metadata__")
                        .take(100)
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                return Ok(json!({
                    "path": path_str,
                    "format": "SafeTensors",
                    "header_size": header_len,
                    "tensor_count": tensor_names.len(),
                    "metadata": val.get("__metadata__"),
                    "sample_tensors": tensor_names,
                    "file_size": bytes.len(),
                    "sha256": sha256,
                }));
            }
        }

        if bytes.len() >= 8 && &bytes[4..8] == b"TFL3" {
            return Ok(json!({
                "path": path_str,
                "format": "TensorFlow_Lite",
                "file_size": bytes.len(),
                "sha256": sha256,
            }));
        }

        Ok(json!({
            "path": path_str,
            "format": "unknown_model_or_binary",
            "file_size": bytes.len(),
            "sha256": sha256,
            "entropy": (Self::calculate_entropy(&bytes) * 1000.0).round() / 1000.0,
        }))
    }

    pub fn inspect_desktop_application(path: &Path) -> Result<Value, Box<dyn Error>> {
        let mut framework = "unknown_native";
        let mut details = json!({});

        if path.is_dir() {
            let app_asar = path.join("resources").join("app.asar");
            let tauri_conf = path.join("tauri.conf.json");

            if app_asar.exists() || path.join("package.json").exists() {
                framework = "electron";
                if app_asar.exists()
                    && let Ok(asar) = crate::asar::AsarArchive::open(&app_asar)
                {
                    details = json!({
                        "asar_path": app_asar.to_string_lossy(),
                        "asar_entries": asar.entries.len(),
                    });
                }
            } else if tauri_conf.exists() || path.join("src-tauri").exists() {
                framework = "tauri";
            }
        } else if path.is_file() {
            if let Ok(tauri_res) = crate::tauri::TauriScanner::audit_path(path, None)
                && tauri_res.info.as_ref().map(|i| i.is_tauri).unwrap_or(false)
            {
                framework = "tauri";
                details = serde_json::to_value(tauri_res)?;
            }
            if framework == "unknown_native"
                && let Ok(fuses) = crate::fuses::inspect_fuses(path)
                && !fuses.slices.is_empty()
            {
                framework = "electron";
                details = serde_json::to_value(fuses)?;
            }
            if framework == "unknown_native" {
                let mg = crate::managed::inspect_managed_artifact(
                    &json!({ "path": path.to_string_lossy() }),
                );
                if mg["is_managed_cli"].as_bool().unwrap_or(false) {
                    framework = "dotnet_managed";
                    details = mg;
                }
            }
            if framework == "unknown_native"
                && let Ok(layout) = Self::inspect_layout(path)
            {
                framework = "native_binary";
                details = serde_json::to_value(layout)?;
            }
        }

        Ok(json!({
            "path": path.to_string_lossy(),
            "framework": framework,
            "details": details,
        }))
    }

    pub fn inspect_python_pyc(path: &Path) -> Result<Value, Box<dyn Error>> {
        let bytes = read_bounded_artifact(path)?;
        if bytes.len() < 16 {
            return Err("File too small for Python pyc".into());
        }
        let magic_u16 = u16::from_le_bytes(bytes[0..2].try_into()?);
        let crlf = &bytes[2..4];
        let is_pyc = crlf == b"\r\n";
        let py_version = match magic_u16 {
            3450..=3459 => "Python 3.11",
            3490..=3499 => "Python 3.12",
            3530..=3539 => "Python 3.13",
            3410..=3419 => "Python 3.10",
            3390..=3399 => "Python 3.9",
            3370..=3379 => "Python 3.8",
            3350..=3359 => "Python 3.7",
            _ => "Unknown Python bytecode version",
        };
        let sha256 = format!("{:x}", Sha256::digest(&bytes));

        Ok(json!({
            "path": path.to_string_lossy(),
            "is_valid_pyc": is_pyc,
            "magic_number": magic_u16,
            "python_version_estimate": py_version,
            "file_size": bytes.len(),
            "sha256": sha256,
        }))
    }

    pub fn export_environment_bundle() -> Value {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let cpus = rayon::current_num_threads();

        let mut available_tools = Vec::new();
        for cmd in &[
            "adb", "gdb", "rizin", "frida", "objdump", "tshark", "jadx", "apktool", "strings",
        ] {
            let available = std::process::Command::new("which")
                .arg(cmd)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if available {
                available_tools.push(cmd.to_string());
            }
        }

        json!({
            "os": os,
            "arch": arch,
            "logical_threads": cpus,
            "backend": "rea-fast (native zero-dependency)",
            "version": env!("CARGO_PKG_VERSION"),
            "system_tools_detected": available_tools,
            "status": "ready"
        })
    }
}

fn read_leb128(bytes: &[u8]) -> (usize, usize) {
    let mut result = 0usize;
    let mut shift = 0;
    let mut consumed = 0;

    for &b in bytes {
        consumed += 1;
        result |= ((b & 0x7f) as usize) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            break;
        }
    }

    (result, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    #[test]
    fn compressed_rust_metadata_bomb_is_refused() {
        use flate2::{Compression, write::ZlibEncoder};
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(&vec![0u8; MAX_RUST_METADATA_BYTES as usize + 1])
            .unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 1024 * 1024);
        assert!(decompress_rust_metadata(&compressed).is_err());
    }

    #[test]
    fn large_native_files_are_rejected_before_reading_into_memory() {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rea_native_{}_{}.bin", std::process::id(), id));
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_NATIVE_ARTIFACT_BYTES + 1).unwrap();
        assert!(read_bounded_artifact(&path).is_err());
        assert!(NativeInspector::inspect_layout(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn entropy_sampling_caps_emitted_chunks_without_losing_true_count() {
        let data = vec![b'X'; 16_384];
        let value = NativeInspector::inspect_byte_entropy(&data, 1);
        assert_eq!(value["total_bytes"], 16_384);
        assert_eq!(value["chunk_count"], 16_384);
        assert_eq!(value["chunks"].as_array().unwrap().len(), 64);
        assert_eq!(value["chunks_truncated"], true);
        assert_eq!(value["chunks"][0]["offset"], 0);
        assert_eq!(value["chunks"][63]["offset"], 63);
    }

    #[test]
    fn test_wasm_parsing() {
        // Minimal valid WASM binary: magic (\0asm) + version (1)
        let sample = b"\0asm\x01\0\0\0";
        let iface = NativeInspector::inspect_wasm(sample);
        assert!(iface.is_wasm);
        assert_eq!(iface.version, 1);
        assert!(iface.sections.is_empty());
    }
}
