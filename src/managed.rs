use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Debug, Default)]
pub struct ClrMetadata {
    pub is_managed: bool,
    pub is_il2cpp: bool,
    pub version: String,
    pub mvid: Option<String>,
    pub streams: Vec<ClrStream>,
    pub strings: Vec<String>,
    pub user_strings: Vec<String>,
    pub type_names: Vec<String>,
    pub method_names: Vec<String>,
    pub pinvoke_imports: Vec<String>,
}

#[derive(Debug)]
pub struct ClrStream {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

pub fn parse_managed_bytes(bytes: &[u8]) -> ClrMetadata {
    let mut meta = ClrMetadata::default();
    if bytes.len() < 64 {
        return meta;
    }

    // Check IL2CPP global-metadata.dat (0xFAB11BAF)
    if bytes.starts_with(&[0xAF, 0x1B, 0xB1, 0xFA]) {
        meta.is_managed = true;
        meta.is_il2cpp = true;
        meta.version = "IL2CPP global-metadata".to_string();
        extract_il2cpp_metadata(bytes, &mut meta);
        return meta;
    }

    // Locate BSJB signature (0x424A5342 in little-endian: b"BSJB")
    if let Some(bsjb_pos) = bytes.windows(4).position(|w| w == b"BSJB") {
        meta.is_managed = true;
        parse_bsjb_root(bytes, bsjb_pos, &mut meta);
    }

    meta
}

fn parse_bsjb_root(bytes: &[u8], pos: usize, meta: &mut ClrMetadata) {
    if pos + 20 > bytes.len() {
        return;
    }

    // BSJB header:
    // 0..4: "BSJB"
    // 4..6: MajorVersion
    // 6..8: MinorVersion
    // 8..12: Reserved
    // 12..16: Version length
    let v_len = u32::from_le_bytes(bytes[pos + 12..pos + 16].try_into().unwrap_or([0; 4])) as usize;
    if pos + 16 + v_len + 4 > bytes.len() {
        return;
    }

    let v_str_raw = &bytes[pos + 16..pos + 16 + v_len];
    let v_str = String::from_utf8_lossy(v_str_raw)
        .trim_matches('\0')
        .to_string();
    meta.version = v_str;

    // After version string:
    // Flags (2 bytes)
    // Streams count (2 bytes)
    let after_v = pos + 16 + v_len;
    if after_v + 4 > bytes.len() {
        return;
    }
    let streams_count =
        u16::from_le_bytes(bytes[after_v + 2..after_v + 4].try_into().unwrap_or([0; 2])) as usize;

    let mut cursor = after_v + 4;
    for _ in 0..streams_count {
        if cursor + 8 > bytes.len() {
            break;
        }
        let stream_offset =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap_or([0; 4]));
        let stream_size =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap_or([0; 4]));
        cursor += 8;

        // Name is null-terminated ASCII padded to 4-byte boundary
        let mut name_bytes = Vec::new();
        while cursor < bytes.len() {
            let b = bytes[cursor];
            cursor += 1;
            if b == 0 {
                break;
            }
            name_bytes.push(b);
        }
        // Round cursor up to 4-byte boundary from start of name
        let name_total = name_bytes.len() + 1;
        let pad = (4 - (name_total % 4)) % 4;
        cursor += pad;

        let name = String::from_utf8_lossy(&name_bytes).to_string();
        meta.streams.push(ClrStream {
            name: name.clone(),
            offset: stream_offset,
            size: stream_size,
        });

        // Parse Stream Content
        let stream_abs = pos + stream_offset as usize;
        let stream_end = (stream_abs + stream_size as usize).min(bytes.len());
        if stream_abs < bytes.len() {
            let stream_data = &bytes[stream_abs..stream_end];
            match name.as_str() {
                "#Strings" => {
                    extract_ascii_strings(stream_data, meta);
                }
                "#US" => {
                    extract_user_strings(stream_data, meta);
                }
                "#GUID" if stream_data.len() >= 16 => {
                    meta.mvid = Some(format_guid(&stream_data[0..16]));
                }
                _ => {}
            }
        }
    }
}

fn extract_ascii_strings(data: &[u8], meta: &mut ClrMetadata) {
    let mut cur = 0;
    while cur < data.len() {
        if let Some(zero) = data[cur..].iter().position(|&b| b == 0) {
            let slice = &data[cur..cur + zero];
            if !slice.is_empty() && slice.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                let s = String::from_utf8_lossy(slice).to_string();
                if s.contains('.') || s.starts_with("I") && s.len() > 3 {
                    meta.type_names.push(s.clone());
                } else if s.starts_with("get_") || s.starts_with("set_") || s.len() > 3 {
                    meta.method_names.push(s.clone());
                }
                if s.ends_with(".dll") || s.ends_with(".so") || s.ends_with(".dylib") {
                    meta.pinvoke_imports.push(s.clone());
                }
                meta.strings.push(s);
            }
            cur += zero + 1;
        } else {
            break;
        }
    }
}

fn extract_user_strings(data: &[u8], meta: &mut ClrMetadata) {
    let mut cur = 1; // 0th byte of #US is usually empty
    while cur < data.len() {
        // Read compressed length (ECMA-335 II.24.2.4)
        let b0 = data[cur];
        let (len, len_bytes) = if (b0 & 0x80) == 0 {
            (b0 as usize, 1)
        } else if (b0 & 0xC0) == 0x80 {
            if cur + 2 > data.len() {
                break;
            }
            (((b0 as usize & 0x3F) << 8) | (data[cur + 1] as usize), 2)
        } else if (b0 & 0xE0) == 0xC0 {
            if cur + 4 > data.len() {
                break;
            }
            (
                ((b0 as usize & 0x1F) << 24)
                    | ((data[cur + 1] as usize) << 16)
                    | ((data[cur + 2] as usize) << 8)
                    | (data[cur + 3] as usize),
                4,
            )
        } else {
            break;
        };

        cur += len_bytes;
        if len == 0 {
            continue;
        }
        if cur + len > data.len() {
            break;
        }

        // String is (len - 1) bytes of UTF-16LE, last byte is terminal flag
        let str_bytes = &data[cur..cur + len.saturating_sub(1)];
        let u16s: Vec<u16> = str_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16_lossy(&u16s);
        if !s.is_empty() {
            meta.user_strings.push(s);
        }

        cur += len;
    }
}

fn extract_il2cpp_metadata(data: &[u8], meta: &mut ClrMetadata) {
    if data.len() < 32 {
        return;
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
    meta.version = format!("IL2CPP metadata version {version}");

    // Scan for printable string tables
    let mut cur = 32;
    while cur < data.len() && meta.strings.len() < 500 {
        if let Some(zero) = data[cur..].iter().position(|&b| b == 0) {
            let slice = &data[cur..cur + zero];
            if slice.len() >= 3 && slice.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                let s = String::from_utf8_lossy(slice).to_string();
                if s.contains('.') {
                    meta.type_names.push(s.clone());
                }
                meta.strings.push(s);
            }
            cur += zero + 1;
        } else {
            break;
        }
    }
}

fn format_guid(b: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3],
        b[2],
        b[1],
        b[0],
        b[5],
        b[4],
        b[7],
        b[6],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

// ---------------------------------------------------------
// Tool Handler Implementations
// ---------------------------------------------------------

pub fn inspect_managed_artifact(args: &Value) -> Value {
    let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let bytes = match fs::read(path_str) {
        Ok(b) => b,
        Err(e) => {
            return json!({ "status": "error", "message": format!("Failed to read {path_str}: {e}") });
        }
    };

    let meta = parse_managed_bytes(&bytes);
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let streams_info: Vec<Value> = meta
        .streams
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "offset": s.offset,
                "size": s.size
            })
        })
        .collect();

    json!({
        "status": "complete",
        "path": path_str,
        "sha256": sha256,
        "is_managed": meta.is_managed,
        "is_il2cpp": meta.is_il2cpp,
        "clr_version": meta.version,
        "mvid": meta.mvid,
        "streams_count": meta.streams.len(),
        "streams": streams_info,
        "types_count": meta.type_names.len(),
        "methods_count": meta.method_names.len(),
        "user_strings_count": meta.user_strings.len(),
        "pinvoke_count": meta.pinvoke_imports.len()
    })
}

pub fn inspect_managed_members(args: &Value) -> Value {
    let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let type_filter = args.get("type_names").and_then(|v| v.as_array());

    let bytes = match fs::read(path_str) {
        Ok(b) => b,
        Err(e) => {
            return json!({ "status": "error", "message": format!("Failed to read {path_str}: {e}") });
        }
    };

    let meta = parse_managed_bytes(&bytes);
    let filter_set: Vec<&str> = type_filter
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let matched_types: Vec<&String> = if filter_set.is_empty() {
        meta.type_names.iter().take(50).collect()
    } else {
        meta.type_names
            .iter()
            .filter(|t| filter_set.iter().any(|f| t.contains(f)))
            .collect()
    };

    json!({
        "status": "complete",
        "path": path_str,
        "matched_types": matched_types,
        "total_types": meta.type_names.len(),
        "sample_methods": meta.method_names.iter().take(50).collect::<Vec<_>>(),
        "sample_user_strings": meta.user_strings.iter().take(50).collect::<Vec<_>>()
    })
}

pub fn inspect_managed_native_boundaries(args: &Value) -> Value {
    let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let bytes = match fs::read(path_str) {
        Ok(b) => b,
        Err(e) => {
            return json!({ "status": "error", "message": format!("Failed to read {path_str}: {e}") });
        }
    };

    let meta = parse_managed_bytes(&bytes);
    let pinvokes: Vec<Value> = meta
        .pinvoke_imports
        .iter()
        .map(|lib| {
            json!({
                "module_ref": lib,
                "boundary_type": "PInvoke/DllImport",
                "verified": false
            })
        })
        .collect();

    json!({
        "status": "complete",
        "path": path_str,
        "native_boundaries_count": pinvokes.len(),
        "boundaries": pinvokes
    })
}

pub fn verify_managed_native_boundaries(_args: &Value) -> Value {
    json!({
        "status": "unavailable",
        "verified": null,
        "unresolved_declarations": null,
        "reason": "No retained boundary declarations or native targets were verified"
    })
}

pub fn compare_managed_members(_args: &Value) -> Value {
    json!({
        "status": "unavailable",
        "members_matched": null,
        "structural_differences": null,
        "reason": "No member identities or method bodies were compared"
    })
}

pub fn project_managed_application_graph(_args: &Value) -> Value {
    json!({
        "status": "unavailable",
        "graph_nodes": null,
        "call_edges": null,
        "managed_type_boundaries": null,
        "reason": "No managed reference graph has been constructed"
    })
}

pub fn import_managed_reconstruction(_args: &Value) -> Value {
    json!({
        "status": "unavailable",
        "imported": false,
        "methods_reconstructed": null,
        "reason": "Managed reconstruction import is not implemented"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_managed_workflows_never_claim_verification() {
        let args = json!({"claims": [], "left": {}, "right": {}});
        assert_eq!(
            verify_managed_native_boundaries(&args)["status"],
            "unavailable"
        );
        assert!(verify_managed_native_boundaries(&args)["verified"].is_null());
        assert!(compare_managed_members(&args)["members_matched"].is_null());
        assert_eq!(
            project_managed_application_graph(&args)["status"],
            "unavailable"
        );
        assert_eq!(import_managed_reconstruction(&args)["imported"], false);
    }

    #[test]
    fn test_bsjb_parsing() {
        // Construct minimal BSJB metadata block
        let mut data = Vec::new();
        // Pad 16 bytes
        data.extend_from_slice(&[0; 16]);
        let bsjb_start = data.len();
        data.extend_from_slice(b"BSJB"); // 0..4
        data.extend_from_slice(&1u16.to_le_bytes()); // major 4..6
        data.extend_from_slice(&1u16.to_le_bytes()); // minor 6..8
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved 8..12
        let version_str = b"v4.0.30319\0\0"; // 12 bytes
        data.extend_from_slice(&(version_str.len() as u32).to_le_bytes()); // 12..16
        data.extend_from_slice(version_str); // 16..28
        data.extend_from_slice(&0u16.to_le_bytes()); // flags
        data.extend_from_slice(&1u16.to_le_bytes()); // 1 stream

        // Stream 0: #Strings
        let str_offset: u32 = 64;
        let str_size: u32 = 64;
        data.extend_from_slice(&str_offset.to_le_bytes());
        data.extend_from_slice(&str_size.to_le_bytes());
        // Name: "#Strings\0" (9 bytes) padded to 12
        data.extend_from_slice(b"#Strings\0\0\0\0");

        // String table at offset 64 from BSJB
        let stream_abs = bsjb_start + str_offset as usize;
        if data.len() < stream_abs {
            data.resize(stream_abs, 0);
        }
        data.extend_from_slice(b"\0MyNamespace.MyClass\0SomeMethod\0");

        let meta = parse_managed_bytes(&data);
        assert!(meta.is_managed);
        assert_eq!(meta.version, "v4.0.30319");
        assert!(meta.type_names.contains(&"MyNamespace.MyClass".to_string()));
    }
}
