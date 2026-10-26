use flate2::read::DeflateDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::Read,
    path::Path,
};

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

impl MobileInspector {
    pub fn parse_zip_entries(bytes: &[u8]) -> Result<Vec<ZipEntry>, Box<dyn Error>> {
        if bytes.len() < 22 {
            return Err("File too small for ZIP archive".into());
        }

        // Scan backwards for EOCD magic 0x06054b50 (PK\x05\x06)
        let mut eocd_pos = None;
        let scan_start = bytes.len().saturating_sub(65535 + 22);
        for i in (scan_start..bytes.len() - 21).rev() {
            if &bytes[i..i + 4] == b"PK\x05\x06" {
                eocd_pos = Some(i);
                break;
            }
        }

        let eocd = match eocd_pos {
            Some(p) => p,
            None => return Err("ZIP End of Central Directory (EOCD) not found".into()),
        };

        let total_entries = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into()?) as usize;
        let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into()?) as usize;
        let cd_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into()?) as usize;

        if cd_offset + cd_size > bytes.len() {
            return Err("Invalid ZIP Central Directory offset".into());
        }

        let cd_bytes = &bytes[cd_offset..cd_offset + cd_size];
        let mut entries = Vec::with_capacity(total_entries);
        let mut cur = 0;

        while cur + 46 <= cd_bytes.len() {
            if &cd_bytes[cur..cur + 4] != b"PK\x01\x02" {
                break;
            }

            let comp_method = u16::from_le_bytes(cd_bytes[cur + 10..cur + 12].try_into()?);
            let comp_size = u32::from_le_bytes(cd_bytes[cur + 20..cur + 24].try_into()?) as u64;
            let uncomp_size = u32::from_le_bytes(cd_bytes[cur + 24..cur + 28].try_into()?) as u64;
            let name_len = u16::from_le_bytes(cd_bytes[cur + 28..cur + 30].try_into()?) as usize;
            let extra_len = u16::from_le_bytes(cd_bytes[cur + 30..cur + 32].try_into()?) as usize;
            let comment_len = u16::from_le_bytes(cd_bytes[cur + 32..cur + 34].try_into()?) as usize;
            let local_offset = u32::from_le_bytes(cd_bytes[cur + 42..cur + 46].try_into()?) as u64;

            cur += 46;
            if cur + name_len > cd_bytes.len() {
                break;
            }

            let name = String::from_utf8_lossy(&cd_bytes[cur..cur + name_len]).to_string();
            cur += name_len + extra_len + comment_len;

            entries.push(ZipEntry {
                name,
                compressed_size: comp_size,
                uncompressed_size: uncomp_size,
                compression_method: comp_method,
                local_header_offset: local_offset,
            });
        }

        Ok(entries)
    }

    pub fn extract_zip_entry(bytes: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, Box<dyn Error>> {
        let offset = entry.local_header_offset as usize;
        if offset + 30 > bytes.len() {
            return Err("Invalid local header offset".into());
        }
        if &bytes[offset..offset + 4] != b"PK\x03\x04" {
            return Err("Invalid local header signature".into());
        }

        let name_len = u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into()?) as usize;
        let extra_len = u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into()?) as usize;
        let data_start = offset + 30 + name_len + extra_len;
        let data_end = data_start + entry.compressed_size as usize;

        if data_end > bytes.len() {
            return Err("Data out of bounds".into());
        }

        let raw_data = &bytes[data_start..data_end];
        match entry.compression_method {
            0 => Ok(raw_data.to_vec()), // Stored
            8 => { // Deflated
                let mut decoder = DeflateDecoder::new(raw_data);
                let mut decompressed = Vec::with_capacity(entry.uncompressed_size as usize);
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            _ => Err("Unsupported compression method".into()),
        }
    }

    pub fn inspect_apk(path: &Path) -> Result<AndroidPackageInfo, Box<dyn Error>> {
        let bytes = fs::read(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let entries = Self::parse_zip_entries(&bytes)?;

        let mut dex_files = Vec::new();
        let mut native_libraries: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut total_uncompressed_bytes = 0u64;
        let mut manifest_entry = None;

        for entry in &entries {
            total_uncompressed_bytes += entry.uncompressed_size;

            if entry.name.ends_with(".dex") {
                let dex_data = Self::extract_zip_entry(&bytes, entry).unwrap_or_default();
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
            if let Ok(manifest_bytes) = Self::extract_zip_entry(&bytes, &entry) {
                let strings = Self::parse_axml_strings(&manifest_bytes);
                for s in &strings {
                    if s.contains("permission.") {
                        permissions.push(s.clone());
                    } else if s.ends_with("Activity") {
                        activities.push(s.clone());
                    } else if s.ends_with("Service") {
                        services.push(s.clone());
                    } else if package_name.is_none() && s.contains('.') && !s.starts_with("http") && !s.starts_with("android.") && s.len() > 3 {
                        if s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_') {
                            package_name = Some(s.clone());
                        }
                    }
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
            let chunk_size = u32::from_le_bytes(bytes[cur + 4..cur + 8].try_into().unwrap_or([0, 0, 0, 0])) as usize;

            if chunk_type == 0x0001 { // RES_STRING_POOL_TYPE
                if cur + 28 <= bytes.len() {
                    let string_count = u32::from_le_bytes(bytes[cur + 8..cur + 12].try_into().unwrap_or([0, 0, 0, 0])) as usize;
                    let flags = u32::from_le_bytes(bytes[cur + 16..cur + 20].try_into().unwrap_or([0, 0, 0, 0]));
                    let strings_start = cur + u32::from_le_bytes(bytes[cur + 20..cur + 24].try_into().unwrap_or([0, 0, 0, 0])) as usize;
                    let is_utf8 = (flags & (1 << 8)) != 0;

                    let offsets_start = cur + 28;
                    for i in 0..string_count {
                        let off_idx = offsets_start + i * 4;
                        if off_idx + 4 > bytes.len() { break; }
                        let str_offset = strings_start + u32::from_le_bytes(bytes[off_idx..off_idx + 4].try_into().unwrap_or([0, 0, 0, 0])) as usize;

                        if is_utf8 {
                            if str_offset + 2 <= bytes.len() {
                                // UTF-8: skip length bytes, read null-terminated or length
                                let len = bytes[str_offset + 1] as usize;
                                let start = str_offset + 2;
                                if start + len <= bytes.len() {
                                    if let Ok(s) = std::str::from_utf8(&bytes[start..start + len]) {
                                        if !s.is_empty() {
                                            strings.push(s.to_string());
                                        }
                                    }
                                }
                            }
                        } else {
                            if str_offset + 2 <= bytes.len() {
                                // UTF-16: 2-byte length
                                let char_len = u16::from_le_bytes(bytes[str_offset..str_offset + 2].try_into().unwrap_or([0, 0])) as usize;
                                let start = str_offset + 2;
                                let byte_len = char_len * 2;
                                if start + byte_len <= bytes.len() {
                                    let u16_chars: Vec<u16> = bytes[start..start + byte_len]
                                        .chunks_exact(2)
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect();
                                    if let Ok(s) = String::from_utf16(&u16_chars) {
                                        if !s.is_empty() {
                                            strings.push(s);
                                        }
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
                if b >= 32 && b <= 126 {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_eocd_empty() {
        // Minimum valid empty zip archive is 22 bytes
        let empty_zip: [u8; 22] = [
            b'P', b'K', 0x05, 0x06, // signature
            0, 0, 0, 0,             // disk numbers
            0, 0, 0, 0,             // entries
            0, 0, 0, 0,             // central directory size
            0, 0, 0, 0,             // central directory offset
            0, 0,                   // comment length
        ];
        let entries = MobileInspector::parse_zip_entries(&empty_zip).unwrap();
        assert!(entries.is_empty());
    }
}
