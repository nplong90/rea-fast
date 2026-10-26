use object::{Object, ObjectSection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};
use flate2::read::ZlibDecoder;
use std::io::Read;

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

pub struct NativeInspector;

impl NativeInspector {
    pub fn inspect_layout(path: &Path) -> Result<BinaryLayout, Box<dyn Error>> {
        let bytes = fs::read(path)?;
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
        let bytes = fs::read(path)?;
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
        let bytes = fs::read(path)?;
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
                if sec.name().unwrap_or("") == ".dep-v0" {
                    if let Ok(data) = sec.data() {
                        let mut decoder = ZlibDecoder::new(data);
                        let mut decompressed = Vec::new();
                        if decoder.read_to_end(&mut decompressed).is_ok() {
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
            }.to_string();

            if id == 7 { // Export section
                Self::parse_wasm_exports(sec_data, &mut exports);
            } else if id == 2 { // Import section
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
        if data.is_empty() { return; }
        let mut cur = 0;
        let (count, shift) = read_leb128(&data[cur..]);
        cur += shift;

        for _ in 0..count {
            if cur >= data.len() { break; }
            let (name_len, s) = read_leb128(&data[cur..]);
            cur += s;
            if cur + name_len > data.len() { break; }
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
        if data.is_empty() { return; }
        let mut cur = 0;
        let (count, shift) = read_leb128(&data[cur..]);
        cur += shift;

        for _ in 0..count {
            if cur >= data.len() { break; }
            let (mod_len, s) = read_leb128(&data[cur..]);
            cur += s;
            if cur + mod_len > data.len() { break; }
            let mod_name = String::from_utf8_lossy(&data[cur..cur + mod_len]).to_string();
            cur += mod_len;

            if cur >= data.len() { break; }
            let (field_len, s2) = read_leb128(&data[cur..]);
            cur += s2;
            if cur + field_len > data.len() { break; }
            let field_name = String::from_utf8_lossy(&data[cur..cur + field_len]).to_string();
            cur += field_len;

            if cur < data.len() {
                let kind = data[cur];
                cur += 1;
                match kind {
                    0 | 1 => { // func or table
                        let (_, idx_shift) = read_leb128(&data[cur..]);
                        cur += idx_shift;
                    }
                    2 => { // memory
                        let (_, idx_shift) = read_leb128(&data[cur..]);
                        cur += idx_shift;
                    }
                    _ => {}
                }
            }
            imports.push(format!("{}.{}", mod_name, field_name));
        }
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
