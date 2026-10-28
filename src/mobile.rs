use flate2::read::DeflateDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fs, io::Read, path::Path};

// APK/ZIP metadata is untrusted. Enforce bounds before bulk reads or inflate.
const MAX_APK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ZIP_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ZIP_DECLARED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 16_384;

#[derive(Debug, Clone, Serialize)]
pub struct DexSummary {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidPackageInfo {
    pub path: String,
    pub sha256: String,
    pub package_name: Option<String>,
    pub permissions: Vec<String>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
    pub dex_files: Vec<DexSummary>,
    pub native_libraries: BTreeMap<String, Vec<String>>, // ABI -> Vec<lib_name>
    pub total_files: usize,
    pub total_uncompressed_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: u16,
    pub local_header_offset: u64,
}

pub struct MobileInspector;

fn find_zip_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }
    let scan_start = bytes.len().saturating_sub(65535 + 22);
    (scan_start..bytes.len() - 21).rev().find(|&i| {
        &bytes[i..i + 4] == b"PK\x05\x06"
            && i + 22 + u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize == bytes.len()
    })
}

/// Only detect structurally located v2/v3 ID-value pairs. This does NOT verify
/// signatures, certificates or Android APK content digests.
fn apk_signing_scheme_ids(bytes: &[u8], central_offset: usize) -> Vec<&'static str> {
    const MAGIC: &[u8; 16] = b"APK Sig Block 42";
    if central_offset < 32 || bytes.get(central_offset - 16..central_offset) != Some(MAGIC) {
        return Vec::new();
    }
    let Some(footer) = bytes.get(central_offset - 24..central_offset - 16) else {
        return Vec::new();
    };
    let size = u64::from_le_bytes(footer.try_into().expect("eight byte footer"));
    if size < 24 || size > (central_offset - 8) as u64 {
        return Vec::new();
    }
    let start = central_offset - 8 - size as usize;
    if bytes.get(start..start + 8) != Some(footer) {
        return Vec::new();
    }
    let end = central_offset - 24;
    let mut cursor = start + 8;
    let mut detected = Vec::new();
    while cursor < end {
        let Some(length_bytes) = bytes.get(cursor..cursor + 8) else {
            return Vec::new();
        };
        let length = u64::from_le_bytes(length_bytes.try_into().expect("eight byte length"));
        let Some(next) = usize::try_from(length)
            .ok()
            .and_then(|len| cursor.checked_add(8)?.checked_add(len))
        else {
            return Vec::new();
        };
        if length <= 4 || next > end {
            return Vec::new();
        }
        let id = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
        match id {
            0x7109_871a if !detected.contains(&"v2") => detected.push("v2"),
            0xf053_68c0 if !detected.contains(&"v3") => detected.push("v3"),
            _ => {}
        }
        cursor = next;
    }
    detected
}

impl MobileInspector {
    fn read_apk_bytes(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
        let file = fs::File::open(path)?;
        if file.metadata()?.len() > MAX_APK_BYTES {
            return Err("APK exceeds 256 MiB input limit".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_APK_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_APK_BYTES {
            return Err("APK grew beyond 256 MiB input limit".into());
        }
        Ok(bytes)
    }

    pub fn parse_zip_entries(bytes: &[u8]) -> Result<Vec<ZipEntry>, Box<dyn Error>> {
        if bytes.len() < 22 {
            return Err("File too small for ZIP archive".into());
        }

        // Scan backwards for an EOCD with a matching trailing comment length.
        let eocd = match find_zip_eocd(bytes) {
            Some(p) => p,
            None => return Err("ZIP End of Central Directory (EOCD) not found".into()),
        };

        let disk = u16::from_le_bytes(bytes[eocd + 4..eocd + 6].try_into()?);
        let central_disk = u16::from_le_bytes(bytes[eocd + 6..eocd + 8].try_into()?);
        let disk_entries = u16::from_le_bytes(bytes[eocd + 8..eocd + 10].try_into()?);
        let total_entries = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into()?) as usize;
        let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into()?) as usize;
        let cd_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into()?) as usize;

        if disk != 0 || central_disk != 0 || disk_entries as usize != total_entries {
            return Err("Multi-disk ZIP archives are unsupported".into());
        }
        if total_entries > MAX_ZIP_ENTRIES || total_entries == u16::MAX as usize {
            return Err("ZIP entry count exceeds supported limit (ZIP64 unsupported)".into());
        }
        if cd_size == u32::MAX as usize || cd_offset == u32::MAX as usize {
            return Err("ZIP64 Central Directory is unsupported".into());
        }
        if cd_offset.checked_add(cd_size) != Some(eocd) {
            return Err("Invalid ZIP Central Directory offset".into());
        }

        let cd_bytes = &bytes[cd_offset..cd_offset + cd_size];
        let mut entries = Vec::with_capacity(total_entries);
        let mut cur = 0;

        let mut total_declared = 0u64;
        for _ in 0..total_entries {
            if cur + 46 > cd_bytes.len() {
                return Err("Truncated ZIP Central Directory".into());
            }
            if &cd_bytes[cur..cur + 4] != b"PK\x01\x02" {
                return Err("Invalid ZIP Central Directory record".into());
            }

            let comp_method = u16::from_le_bytes(cd_bytes[cur + 10..cur + 12].try_into()?);
            let comp_size = u32::from_le_bytes(cd_bytes[cur + 20..cur + 24].try_into()?) as u64;
            let uncomp_size = u32::from_le_bytes(cd_bytes[cur + 24..cur + 28].try_into()?) as u64;
            let name_len = u16::from_le_bytes(cd_bytes[cur + 28..cur + 30].try_into()?) as usize;
            let extra_len = u16::from_le_bytes(cd_bytes[cur + 30..cur + 32].try_into()?) as usize;
            let comment_len = u16::from_le_bytes(cd_bytes[cur + 32..cur + 34].try_into()?) as usize;
            let local_offset = u32::from_le_bytes(cd_bytes[cur + 42..cur + 46].try_into()?) as u64;

            cur += 46;
            let record_end = cur
                .checked_add(name_len)
                .and_then(|v| v.checked_add(extra_len))
                .and_then(|v| v.checked_add(comment_len))
                .ok_or("ZIP Central Directory record overflow")?;
            if record_end > cd_bytes.len() {
                return Err("Truncated ZIP Central Directory record".into());
            }

            let name = std::str::from_utf8(&cd_bytes[cur..cur + name_len])?.to_string();
            cur = record_end;
            total_declared = total_declared
                .checked_add(uncomp_size)
                .ok_or("ZIP declared size overflow")?;
            if total_declared > MAX_ZIP_DECLARED_BYTES {
                return Err("ZIP declared uncompressed size exceeds 512 MiB limit".into());
            }

            entries.push(ZipEntry {
                name,
                compressed_size: comp_size,
                uncompressed_size: uncomp_size,
                compression_method: comp_method,
                local_header_offset: local_offset,
            });
        }

        if cur != cd_bytes.len() {
            return Err("ZIP Central Directory contains unparsed records".into());
        }
        Ok(entries)
    }

    pub fn extract_zip_entry(bytes: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, Box<dyn Error>> {
        if entry.uncompressed_size > MAX_ZIP_ENTRY_BYTES {
            return Err("ZIP member exceeds 64 MiB extraction limit".into());
        }
        let offset = usize::try_from(entry.local_header_offset)?;
        if offset.checked_add(30).is_none_or(|v| v > bytes.len()) {
            return Err("Invalid local header offset".into());
        }
        if &bytes[offset..offset + 4] != b"PK\x03\x04" {
            return Err("Invalid local header signature".into());
        }

        let name_len = u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into()?) as usize;
        let extra_len = u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into()?) as usize;
        let local_method = u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into()?);
        if local_method != entry.compression_method {
            return Err("ZIP local and central compression methods disagree".into());
        }
        let name_start = offset + 30;
        let data_start = name_start
            .checked_add(name_len)
            .and_then(|v| v.checked_add(extra_len))
            .ok_or("ZIP local header overflow")?;
        let data_end = data_start
            .checked_add(usize::try_from(entry.compressed_size)?)
            .ok_or("ZIP member data extent overflow")?;

        if data_end > bytes.len() || data_start > bytes.len() {
            return Err("Data out of bounds".into());
        }
        if bytes[name_start..name_start + name_len] != *entry.name.as_bytes() {
            return Err("ZIP local and central member names disagree".into());
        }

        let raw_data = &bytes[data_start..data_end];
        let decompressed = match entry.compression_method {
            0 => raw_data.to_vec(), // Stored
            8 => {
                // Deflated
                let mut decoder = DeflateDecoder::new(raw_data);
                let mut decompressed = Vec::new();
                // A forged small uncompressed_size must never bypass the cap.
                let mut decoder = (&mut decoder).take(MAX_ZIP_ENTRY_BYTES + 1);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            _ => return Err("Unsupported compression method".into()),
        };
        if decompressed.len() as u64 > MAX_ZIP_ENTRY_BYTES {
            return Err("Inflated ZIP member exceeds 64 MiB limit".into());
        }
        if decompressed.len() as u64 != entry.uncompressed_size {
            return Err("ZIP member decompressed length disagrees with Central Directory".into());
        }
        Ok(decompressed)
    }

    pub fn inspect_apk(path: &Path) -> Result<AndroidPackageInfo, Box<dyn Error>> {
        let bytes = Self::read_apk_bytes(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let entries = Self::parse_zip_entries(&bytes)?;

        let mut dex_files = Vec::new();
        let mut native_libraries: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut total_uncompressed_bytes = 0u64;
        let mut manifest_entry = None;

        for entry in &entries {
            total_uncompressed_bytes = total_uncompressed_bytes
                .checked_add(entry.uncompressed_size)
                .ok_or("APK uncompressed size overflow")?;

            if entry.name.ends_with(".dex") {
                let dex_data = Self::extract_zip_entry(&bytes, entry)?;
                let dex_sha = format!("{:x}", Sha256::digest(&dex_data));
                dex_files.push(DexSummary {
                    name: entry.name.clone(),
                    size: entry.uncompressed_size,
                    sha256: dex_sha,
                });
            } else if entry.name.starts_with("lib/") && entry.name.ends_with(".so") {
                let parts: Vec<&str> = entry.name.split('/').collect();
                if parts.len() >= 3 {
                    let abi = parts[1].to_string();
                    let lib_name = parts[2].to_string();
                    native_libraries.entry(abi).or_default().push(lib_name);
                }
            } else if entry.name == "AndroidManifest.xml" {
                manifest_entry = Some(entry.clone());
            }
        }

        let mut package_name = None;
        let mut permissions = Vec::new();
        let mut activities = Vec::new();
        let mut services = Vec::new();

        if let Some(entry) = manifest_entry {
            let manifest_bytes = Self::extract_zip_entry(&bytes, &entry)?;
            let strings = Self::parse_axml_strings(&manifest_bytes);
            for s in &strings {
                if s.contains("permission.") {
                    permissions.push(s.clone());
                } else if s.ends_with("Activity") {
                    activities.push(s.clone());
                } else if s.ends_with("Service") {
                    services.push(s.clone());
                } else if package_name.is_none()
                    && s.contains('.')
                    && !s.starts_with("http")
                    && !s.starts_with("android.")
                    && s.len() > 3
                    && s.chars()
                        .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
                {
                    package_name = Some(s.clone());
                }
            }
        }

        permissions.sort();
        permissions.dedup();
        activities.sort();
        activities.dedup();
        services.sort();
        services.dedup();

        Ok(AndroidPackageInfo {
            path: path.to_string_lossy().to_string(),
            sha256,
            package_name,
            permissions,
            activities,
            services,
            dex_files,
            native_libraries,
            total_files: entries.len(),
            total_uncompressed_bytes,
        })
    }

    /// Extract strings from Android Binary XML (AXML) String Pool
    fn parse_axml_strings(bytes: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        if bytes.len() < 8 {
            return strings;
        }

        // Find String Pool Chunk: type 0x0001001c or 0x0001
        let mut cur = 8;
        while cur + 8 <= bytes.len() {
            let chunk_type = u16::from_le_bytes(bytes[cur..cur + 2].try_into().unwrap_or([0, 0]));
            let chunk_size =
                u32::from_le_bytes(bytes[cur + 4..cur + 8].try_into().unwrap_or([0, 0, 0, 0]))
                    as usize;

            if chunk_type == 0x0001 {
                // RES_STRING_POOL_TYPE
                if cur + 28 <= bytes.len() {
                    let string_count = u32::from_le_bytes(
                        bytes[cur + 8..cur + 12].try_into().unwrap_or([0, 0, 0, 0]),
                    ) as usize;
                    let flags = u32::from_le_bytes(
                        bytes[cur + 16..cur + 20].try_into().unwrap_or([0, 0, 0, 0]),
                    );
                    let strings_start = cur
                        + u32::from_le_bytes(
                            bytes[cur + 20..cur + 24].try_into().unwrap_or([0, 0, 0, 0]),
                        ) as usize;
                    let is_utf8 = (flags & (1 << 8)) != 0;

                    let offsets_start = cur + 28;
                    for i in 0..string_count {
                        let off_idx = offsets_start + i * 4;
                        if off_idx + 4 > bytes.len() {
                            break;
                        }
                        let str_offset = strings_start
                            + u32::from_le_bytes(
                                bytes[off_idx..off_idx + 4]
                                    .try_into()
                                    .unwrap_or([0, 0, 0, 0]),
                            ) as usize;

                        if is_utf8 {
                            if str_offset + 2 <= bytes.len() {
                                // UTF-8: skip length bytes, read null-terminated or length
                                let len = bytes[str_offset + 1] as usize;
                                let start = str_offset + 2;
                                if start + len <= bytes.len()
                                    && let Ok(s) = std::str::from_utf8(&bytes[start..start + len])
                                    && !s.is_empty()
                                {
                                    strings.push(s.to_string());
                                }
                            }
                        } else {
                            if str_offset + 2 <= bytes.len() {
                                // UTF-16: 2-byte length
                                let char_len = u16::from_le_bytes(
                                    bytes[str_offset..str_offset + 2]
                                        .try_into()
                                        .unwrap_or([0, 0]),
                                ) as usize;
                                let start = str_offset + 2;
                                let byte_len = char_len * 2;
                                if start + byte_len <= bytes.len() {
                                    let u16_chars: Vec<u16> = bytes[start..start + byte_len]
                                        .as_chunks::<2>()
                                        .0
                                        .iter()
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect();
                                    if let Ok(s) = String::from_utf16(&u16_chars)
                                        && !s.is_empty()
                                    {
                                        strings.push(s);
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            }

            if chunk_size == 0 || cur + chunk_size > bytes.len() {
                break;
            }
            cur += chunk_size;
        }

        // Fallback: simple printable ASCII string scan if AXML pool parsing was incomplete
        if strings.is_empty() {
            let mut buf = Vec::new();
            for &b in bytes {
                if (32..=126).contains(&b) {
                    buf.push(b);
                } else {
                    if buf.len() >= 4 {
                        strings.push(String::from_utf8_lossy(&buf).to_string());
                    }
                    buf.clear();
                }
            }
        }

        strings
    }

    pub fn identify_flutter_build(path: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut is_flutter = false;
        let mut has_libflutter = false;
        let mut has_app_lib = false;
        let mut has_flutter_assets = false;
        let mut has_snapshot_data = false;
        let mut artifacts_found = Vec::new();

        if path.is_file() {
            let bytes = Self::read_apk_bytes(path)?;
            let entries = Self::parse_zip_entries(&bytes)?;
            for e in entries {
                let name = e.name.to_lowercase();
                if name.contains("libflutter.so") {
                    is_flutter = true;
                    has_libflutter = true;
                    artifacts_found.push(e.name);
                } else if name.contains("libapp.so") {
                    is_flutter = true;
                    has_app_lib = true;
                    artifacts_found.push(e.name);
                } else if name.contains("flutter_assets") {
                    is_flutter = true;
                    has_flutter_assets = true;
                    artifacts_found.push(e.name);
                } else if name.contains("isolate_snapshot")
                    || name.contains("vm_snapshot")
                    || name.contains("kernel_blob.bin")
                {
                    is_flutter = true;
                    has_snapshot_data = true;
                    artifacts_found.push(e.name);
                }
            }
        } else if path.is_dir() {
            for entry in ignore::WalkBuilder::new(path).build().flatten() {
                let p_str = entry.path().to_string_lossy().to_lowercase();
                if p_str.contains("libflutter.so") {
                    is_flutter = true;
                    has_libflutter = true;
                    artifacts_found.push(entry.path().to_string_lossy().to_string());
                } else if p_str.contains("libapp.so") {
                    is_flutter = true;
                    has_app_lib = true;
                    artifacts_found.push(entry.path().to_string_lossy().to_string());
                } else if p_str.contains("flutter_assets") {
                    is_flutter = true;
                    has_flutter_assets = true;
                    artifacts_found.push(entry.path().to_string_lossy().to_string());
                } else if p_str.contains("isolate_snapshot")
                    || p_str.contains("vm_snapshot")
                    || p_str.contains("kernel_blob.bin")
                {
                    is_flutter = true;
                    has_snapshot_data = true;
                    artifacts_found.push(entry.path().to_string_lossy().to_string());
                }
            }
        }

        artifacts_found.sort();
        artifacts_found.dedup();
        if artifacts_found.len() > 50 {
            artifacts_found.truncate(50);
        }

        Ok(serde_json::json!({
            "path": path.to_string_lossy(),
            "is_flutter": is_flutter,
            "has_libflutter": has_libflutter,
            "has_dart_aot_libapp": has_app_lib,
            "has_flutter_assets": has_flutter_assets,
            "has_snapshot_data": has_snapshot_data,
            "detected_artifacts": artifacts_found,
            "build_type": if has_app_lib { "release_aot" } else if is_flutter { "debug_jit" } else { "non_flutter" }
        }))
    }

    pub fn inspect_apk_signature(path: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
        let bytes = Self::read_apk_bytes(path)?;
        let mut v1_files = Vec::new();
        let mut has_v1 = false;
        let mut schemes = Vec::new();

        let entries = Self::parse_zip_entries(&bytes)?;
        for e in entries {
            if e.name.starts_with("META-INF/") {
                let upper = e.name.to_uppercase();
                if upper.ends_with(".RSA")
                    || upper.ends_with(".DSA")
                    || upper.ends_with(".EC")
                    || upper.ends_with(".SF")
                {
                    v1_files.push(e.name);
                    has_v1 = true;
                }
            }
        }
        if has_v1 {
            schemes.push("v1_jar_signature");
        }

        let eocd = find_zip_eocd(&bytes).ok_or("Valid ZIP EOCD not found")?;
        let central_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into()?) as usize;
        let detected_scheme_ids = apk_signing_scheme_ids(&bytes, central_offset);
        let has_v2_or_v3 = !detected_scheme_ids.is_empty();
        if has_v2_or_v3 {
            schemes.push("v2_or_v3_apk_signature_scheme");
        }

        Ok(serde_json::json!({
            "path": path.to_string_lossy(),
            "has_v1_jar_signing": has_v1,
            "v1_signing_files": v1_files,
            "has_v2_or_v3_signing": has_v2_or_v3,
            "detected_scheme_ids": detected_scheme_ids,
            "signature_cryptographic_verification": "not_performed",
            "schemes": schemes,
            "file_size": bytes.len(),
            "sha256": format!("{:x}", Sha256::digest(&bytes))
        }))
    }

    pub fn project_android_application_graph(
        path: &Path,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        let info = Self::inspect_apk(path)?;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        let app_id = info
            .package_name
            .clone()
            .unwrap_or_else(|| "android_app".to_string());
        nodes.push(serde_json::json!({
            "id": app_id,
            "kind": "application",
            "sha256": info.sha256
        }));

        for act in &info.activities {
            let act_id = format!("{app_id}:{act}");
            nodes.push(serde_json::json!({ "id": act_id, "kind": "activity", "name": act }));
            edges.push(serde_json::json!({ "source": app_id, "target": act_id, "kind": "declares_activity" }));
        }

        for srv in &info.services {
            let srv_id = format!("{app_id}:{srv}");
            nodes.push(serde_json::json!({ "id": srv_id, "kind": "service", "name": srv }));
            edges.push(serde_json::json!({ "source": app_id, "target": srv_id, "kind": "declares_service" }));
        }

        for perm in &info.permissions {
            let perm_id = format!("permission:{perm}");
            nodes.push(serde_json::json!({ "id": perm_id, "kind": "permission", "name": perm }));
            edges.push(serde_json::json!({ "source": app_id, "target": perm_id, "kind": "requests_permission" }));
        }

        for (abi, libs) in &info.native_libraries {
            for lib in libs {
                let lib_id = format!("native_lib:{abi}:{lib}");
                nodes.push(serde_json::json!({ "id": lib_id, "kind": "native_library", "abi": abi, "name": lib }));
                edges.push(serde_json::json!({ "source": app_id, "target": lib_id, "kind": "bundles_native_lib" }));
            }
        }

        Ok(serde_json::json!({
            "package_name": info.package_name,
            "total_nodes": nodes.len(),
            "total_edges": edges.len(),
            "nodes": nodes,
            "edges": edges,
            "dex_count": info.dex_files.len(),
            "status": "complete"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::DeflateEncoder};
    use std::{io::Write, time::SystemTime};

    fn test_zip(name: &str, method: u16, data: &[u8], declared_size: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Local file header (CRC is not currently used for verification).
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&method.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]); // time/date + CRC32
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&declared_size.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(data);
        let central_offset = bytes.len() as u32;

        bytes.extend_from_slice(b"PK\x01\x02");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&method.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]); // time/date + CRC32
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&declared_size.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 8]); // extra/comment/disk/internal attributes
        bytes.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        bytes.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        bytes.extend_from_slice(name.as_bytes());
        let central_size = bytes.len() as u32 - central_offset;

        bytes.extend_from_slice(b"PK\x05\x06");
        bytes.extend_from_slice(&[0; 4]); // disk IDs
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&central_size.to_le_bytes());
        bytes.extend_from_slice(&central_offset.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    fn test_apk_path() -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rea-mobile-{}-{now}.apk", std::process::id()))
    }

    #[test]
    fn test_zip_eocd_empty() {
        // Minimum valid empty zip archive is 22 bytes
        let empty_zip: [u8; 22] = [
            b'P', b'K', 0x05, 0x06, // signature
            0, 0, 0, 0, // disk numbers
            0, 0, 0, 0, // entries
            0, 0, 0, 0, // central directory size
            0, 0, 0, 0, // central directory offset
            0, 0, // comment length
        ];
        let entries = MobileInspector::parse_zip_entries(&empty_zip).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn valid_stored_dex_has_real_content_digest() {
        let dex = b"dex\nreal-content";
        let path = test_apk_path();
        fs::write(&path, test_zip("classes.dex", 0, dex, dex.len() as u32)).unwrap();

        let result = MobileInspector::inspect_apk(&path).unwrap();
        assert_eq!(result.total_files, 1);
        assert_eq!(result.dex_files.len(), 1);
        assert_eq!(result.dex_files[0].size, dex.len() as u64);
        assert_eq!(
            result.dex_files[0].sha256,
            format!("{:x}", Sha256::digest(dex))
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn corrupt_dex_cannot_be_reported_as_successful_empty_digest() {
        let path = test_apk_path();
        fs::write(&path, test_zip("classes.dex", 8, b"invalid-deflate", 33)).unwrap();
        assert!(MobileInspector::inspect_apk(&path).is_err());
        assert!(MobileInspector::project_android_application_graph(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn forged_zip_central_count_or_size_is_rejected() {
        let mut bytes = test_zip("classes.dex", 0, b"x", 1);
        let eocd = bytes.len() - 22;
        bytes[eocd + 10..eocd + 12].copy_from_slice(&2u16.to_le_bytes());
        assert!(MobileInspector::parse_zip_entries(&bytes).is_err());

        let mut bytes = test_zip("classes.dex", 0, b"x", 1);
        let eocd = bytes.len() - 22;
        bytes[eocd + 12..eocd + 16].copy_from_slice(&10u32.to_le_bytes());
        assert!(MobileInspector::parse_zip_entries(&bytes).is_err());

        let mut bytes = test_zip("classes.dex", 0, b"x", 1);
        bytes.pop();
        assert!(MobileInspector::parse_zip_entries(&bytes).is_err());
    }

    #[test]
    fn zip_decompression_must_match_declared_size() {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(b"real-dex").unwrap();
        let compressed = encoder.finish().unwrap();
        let bytes = test_zip("classes.dex", 8, &compressed, 2);
        let entry = &MobileInspector::parse_zip_entries(&bytes).unwrap()[0];
        assert!(MobileInspector::extract_zip_entry(&bytes, entry).is_err());
    }

    #[test]
    fn zip_bomb_expansion_stops_at_fixed_limit() {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        let zero_block = [0u8; 1024 * 1024];
        for _ in 0..65 {
            encoder.write_all(&zero_block).unwrap();
        }
        let compressed = encoder.finish().unwrap();
        // The header lies about expansion; the inflater must enforce its own limit.
        let bytes = test_zip("classes.dex", 8, &compressed, 1);
        let entry = &MobileInspector::parse_zip_entries(&bytes).unwrap()[0];
        assert!(MobileInspector::extract_zip_entry(&bytes, entry).is_err());
    }

    #[test]
    fn apk_input_larger_than_limit_is_rejected_before_bulk_allocation() {
        let path = test_apk_path();
        fs::File::create(&path)
            .unwrap()
            .set_len(MAX_APK_BYTES + 1)
            .unwrap();
        assert!(MobileInspector::inspect_apk(&path).is_err());
        assert!(MobileInspector::inspect_apk_signature(&path).is_err());
        assert!(MobileInspector::identify_flutter_build(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn apk_signature_marker_inside_file_does_not_forge_v2_or_v3() {
        let path = test_apk_path();
        let bytes = test_zip("classes.dex", 0, b"junk APK Sig Block 42 junk", 26);
        fs::write(&path, bytes).unwrap();
        let result = MobileInspector::inspect_apk_signature(&path).unwrap();
        assert_eq!(result["has_v2_or_v3_signing"], false);
        assert_eq!(
            result["signature_cryptographic_verification"],
            "not_performed"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn structurally_located_apk_v2_id_is_detected_but_never_marked_verified() {
        let mut bytes = test_zip("classes.dex", 0, b"dex\n", 4);
        let eocd = bytes.len() - 22;
        let central = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let mut pair = Vec::new();
        pair.extend_from_slice(&5u64.to_le_bytes()); // ID + one dummy value byte
        pair.extend_from_slice(&0x7109_871au32.to_le_bytes());
        pair.push(0x00);
        let size = pair.len() as u64 + 24;
        let mut signing = Vec::new();
        signing.extend_from_slice(&size.to_le_bytes());
        signing.extend_from_slice(&pair);
        signing.extend_from_slice(&size.to_le_bytes());
        signing.extend_from_slice(b"APK Sig Block 42");
        bytes.splice(central..central, signing.iter().copied());
        let new_eocd = eocd + signing.len();
        bytes[new_eocd + 16..new_eocd + 20]
            .copy_from_slice(&((central + signing.len()) as u32).to_le_bytes());

        let path = test_apk_path();
        fs::write(&path, bytes).unwrap();
        let result = MobileInspector::inspect_apk_signature(&path).unwrap();
        assert_eq!(result["has_v2_or_v3_signing"], true);
        assert_eq!(result["detected_scheme_ids"], serde_json::json!(["v2"]));
        assert_eq!(
            result["signature_cryptographic_verification"],
            "not_performed"
        );
        fs::remove_file(path).unwrap();
    }
}
