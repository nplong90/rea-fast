use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const SENTINEL: &[u8; 32] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const CHUNK_SIZE: usize = 256 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SENTINELS: usize = 32;

const V1_NAMES: &[&str] = &[
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
    "WasmTrapHandlers",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FuseState {
    Disabled,
    Enabled,
    Removed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuseRecord {
    pub name: String,
    pub index: u8,
    pub state: FuseState,
    pub raw_byte: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuseSlice {
    pub offset: u64,
    pub wire_version: u8,
    pub fuses: Vec<FuseRecord>,
    pub implications: FuseImplications,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FuseImplications {
    pub node_cli_inspect_arguments: &'static str,
    pub electron_run_as_node: &'static str,
    pub embedded_asar_integrity_validation: &'static str,
    pub only_load_app_from_asar: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuseReport {
    pub path: String,
    pub sha256: String,
    pub format: BinaryFormat,
    pub slices: Vec<FuseSlice>,
}

fn detect_format(header: &[u8]) -> Option<BinaryFormat> {
    if header.len() < 4 {
        return None;
    }
    if header.starts_with(b"\x7fELF") {
        return Some(BinaryFormat::Elf);
    }
    if header.starts_with(b"MZ") {
        return Some(BinaryFormat::Pe);
    }
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if matches!(
        magic,
        0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe | 0xcafebabf | 0xbebafeca | 0xbfbafeca
    ) {
        return Some(BinaryFormat::MachO);
    }
    None
}

pub fn resolve_electron_binary(path: &Path) -> Result<PathBuf, io::Error> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    if path.is_dir() && path.extension().and_then(|s| s.to_str()) == Some("app") {
        let candidates = [
            "Contents/Frameworks/Electron Framework.framework/Versions/Current/Electron Framework",
            "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
            "Contents/Frameworks/Electron Framework.framework/Electron Framework",
        ];
        for rel in candidates {
            let candidate = path.join(rel);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "No Electron binary found at path"))
}

pub fn inspect_fuses(path: &Path) -> Result<FuseReport, Box<dyn std::error::Error>> {
    let resolved = resolve_electron_binary(path)?;
    let mut file = File::open(&resolved)?;
    let len = file.metadata()?.len();
    if len > MAX_FILE_BYTES {
        return Err(format!("File exceeds {MAX_FILE_BYTES} bytes").into());
    }

    let mut header = [0u8; 16];
    let n = file.read(&mut header)?;
    let format = detect_format(&header[..n]).ok_or("Unsupported binary format")?;

    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut carry = Vec::with_capacity(SENTINEL.len() - 1);
    let mut file_offset = 0u64;
    let mut sentinel_offsets = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);

        let chunk = &buf[..read];
        let mut scan_buf = Vec::with_capacity(carry.len() + read);
        scan_buf.extend_from_slice(&carry);
        scan_buf.extend_from_slice(chunk);

        let carry_len = carry.len();
        for (i, window) in scan_buf.windows(SENTINEL.len()).enumerate() {
            if window == SENTINEL {
                let hit_offset = file_offset + i as u64 - carry_len as u64;
                sentinel_offsets.push(hit_offset);
                if sentinel_offsets.len() >= MAX_SENTINELS {
                    break;
                }
            }
        }

        let keep = (SENTINEL.len() - 1).min(scan_buf.len());
        carry.clear();
        carry.extend_from_slice(&scan_buf[scan_buf.len() - keep..]);
        file_offset += read as u64;
    }

    let sha256 = format!("{:x}", hasher.finalize());
    let mut slices = Vec::new();

    for offset in sentinel_offsets {
        file.seek(SeekFrom::Start(offset + SENTINEL.len() as u64))?;
        let mut wire_hdr = [0u8; 2];
        if file.read_exact(&mut wire_hdr).is_err() {
            continue;
        }
        let wire_version = wire_hdr[0];
        let declared_length = wire_hdr[1] as usize;
        let mut fuse_bytes = vec![0u8; declared_length];
        if file.read_exact(&mut fuse_bytes).is_err() {
            continue;
        }

        let fuses: Vec<FuseRecord> = fuse_bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let name = V1_NAMES.get(i).copied().unwrap_or("<unknown>").to_string();
                let state = match b {
                    0x30 => FuseState::Disabled,
                    0x31 => FuseState::Enabled,
                    0x72 => FuseState::Removed,
                    _ => FuseState::Unknown,
                };
                FuseRecord {
                    name,
                    index: i as u8,
                    state,
                    raw_byte: b,
                }
            })
            .collect();

        let state_at = |idx: usize| fuses.get(idx).map(|f| f.state).unwrap_or(FuseState::Unknown);

        let node_cli = match state_at(3) {
            FuseState::Enabled => "honored",
            FuseState::Disabled | FuseState::Removed => "not_honored",
            FuseState::Unknown => "unknown",
        };

        let run_as_node = match state_at(0) {
            FuseState::Enabled => "honored",
            FuseState::Disabled | FuseState::Removed => "not_honored",
            FuseState::Unknown => "unknown",
        };

        // embedded_asar_integrity_validation: Mach-O/PE only, ELF is always unknown
        let asar_integrity = match format {
            BinaryFormat::Elf => "unknown",
            BinaryFormat::MachO | BinaryFormat::Pe => match state_at(4) {
                FuseState::Enabled => "enforced",
                FuseState::Disabled | FuseState::Removed => "not_enforced",
                FuseState::Unknown => "unknown",
            },
        };

        let only_load_asar = match state_at(5) {
            FuseState::Enabled => "restricted_to_app_asar",
            FuseState::Disabled | FuseState::Removed => "not_restricted_to_app_asar",
            FuseState::Unknown => "unknown",
        };

        let implications = FuseImplications {
            node_cli_inspect_arguments: node_cli,
            electron_run_as_node: run_as_node,
            embedded_asar_integrity_validation: asar_integrity,
            only_load_app_from_asar: only_load_asar,
        };

        slices.push(FuseSlice {
            offset,
            wire_version,
            fuses,
            implications,
        });
    }

    Ok(FuseReport {
        path: path.to_string_lossy().to_string(),
        sha256,
        format,
        slices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_fuses_in_elf_binary() {
        let temp = std::env::temp_dir().join("test_elf_fuses");
        let mut f = File::create(&temp).unwrap();
        // ELF header prefix
        f.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
        f.write_all(&[0u8; 1024]).unwrap();
        f.write_all(SENTINEL).unwrap();
        f.write_all(&[1u8, 9u8]).unwrap(); // version 1, length 9
        f.write_all(&[0x31, 0x31, 0x31, 0x30, 0x31, 0x31, 0x31, 0x31, 0x31]).unwrap(); // fuse 3 disabled (0x30)
        drop(f);

        let report = inspect_fuses(&temp).unwrap();
        assert_eq!(report.format, BinaryFormat::Elf);
        assert_eq!(report.slices.len(), 1);
        assert_eq!(report.slices[0].fuses.len(), 9);
        assert_eq!(report.slices[0].fuses[3].name, "EnableNodeCliInspectArguments");
        assert_eq!(report.slices[0].fuses[3].state, FuseState::Disabled);
        assert_eq!(report.slices[0].implications.node_cli_inspect_arguments, "not_honored");
        assert_eq!(report.slices[0].implications.embedded_asar_integrity_validation, "unknown");

        let _ = std::fs::remove_file(temp);
    }
}
