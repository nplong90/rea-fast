use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

#[cfg(unix)]
use std::os::unix::fs::{FileExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::FileExt;

const MAX_HEADER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LISTING_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityPolicy {
    #[default]
    Fail,
    RecordAndContinue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub integrity_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityContradiction {
    pub path: String,
    pub expected_hash: String,
    pub observed_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub output_directory: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub files: Vec<ExtractedFile>,
    pub contradictions: Vec<IntegrityContradiction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AsarIntegrity {
    pub algorithm: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum AsarOffset {
    Str(String),
    Num(u64),
}

#[derive(Debug, Clone, Deserialize)]
struct AsarNode {
    files: Option<BTreeMap<String, AsarNode>>,
    #[allow(dead_code)]
    link: Option<String>,
    size: Option<u64>,
    offset: Option<AsarOffset>,
    unpacked: Option<bool>,
    executable: Option<bool>,
    integrity: Option<AsarIntegrity>,
}

#[derive(Debug, Clone)]
pub struct AsarEntry {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    pub unpacked: bool,
    pub executable: bool,
    pub integrity: Option<AsarIntegrity>,
}

pub struct AsarArchive {
    path: PathBuf,
    file: File,
    header_size: u64,
    pub entries: Vec<AsarEntry>,
}

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        let mut read = 0;
        while read < buf.len() {
            let n = file.seek_read(&mut buf[read..], offset + read as u64)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF"));
            }
            read += n;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::Seek;
        let mut f = file.try_clone()?;
        f.seek(io::SeekFrom::Start(offset))?;
        f.read_exact(buf)
    }
}

impl AsarArchive {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let meta = file.metadata()?;
        let file_size = meta.len();
        if file_size < 16 {
            return Err("ASAR archive too small for Pickle header".into());
        }

        let mut prefix = [0u8; 16];
        read_exact_at(&file, &mut prefix, 0)?;

        let size_payload = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        let header_size = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]) as u64;
        let payload_size = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as u64;
        let json_len = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]) as u64;

        if size_payload != 4 || header_size < 8 || payload_size != header_size - 4 || json_len > payload_size - 4 {
            return Err("ASAR header has invalid Pickle extents".into());
        }
        if header_size > file_size.saturating_sub(8) {
            return Err("ASAR header leaves its container".into());
        }
        if header_size > MAX_HEADER_BYTES {
            return Err(format!("ASAR header exceeds {MAX_HEADER_BYTES} byte limit").into());
        }

        let mut json_bytes = vec![0u8; json_len as usize];
        read_exact_at(&file, &mut json_bytes, 16)?;

        // Validate JSON begins with object token (ignoring whitespace)
        let first_non_ws = json_bytes.iter().find(|&&b| !matches!(b, 0x20 | 0x09 | 0x0a | 0x0d));
        if first_non_ws != Some(&b'{') {
            return Err("ASAR header is not a JSON object".into());
        }

        let root: AsarNode = serde_json::from_slice(&json_bytes)?;
        let files = root.files.ok_or("ASAR root has no files table")?;

        let mut entries = Vec::new();
        let mut retained_bytes = 0;
        Self::collect_entries(files, "", &mut entries, &mut retained_bytes)?;
        entries.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self {
            path: path.to_path_buf(),
            file,
            header_size,
            entries,
        })
    }

    fn collect_entries(
        files: BTreeMap<String, AsarNode>,
        parent: &str,
        entries: &mut Vec<AsarEntry>,
        retained_bytes: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (name, node) in files {
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\0')
                || (cfg!(windows) && name.contains('\\'))
            {
                return Err(format!("ASAR header has unsafe path component: {name}").into());
            }

            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };

            *retained_bytes += path.len() * 2 + 256;
            if *retained_bytes > MAX_LISTING_BYTES {
                return Err("ASAR expanded listing exceeds 64 MiB limit".into());
            }

            if let Some(subfiles) = node.files {
                Self::collect_entries(subfiles, &path, entries, retained_bytes)?;
            } else if let Some(size) = node.size {
                let offset = match node.offset {
                    Some(AsarOffset::Str(s)) => s.parse::<u64>().unwrap_or(0),
                    Some(AsarOffset::Num(n)) => n,
                    None => 0,
                };
                entries.push(AsarEntry {
                    path,
                    size,
                    offset,
                    unpacked: node.unpacked.unwrap_or(false),
                    executable: node.executable.unwrap_or(false),
                    integrity: node.integrity,
                });
            }
        }
        Ok(())
    }

    pub fn read_file(&self, entry: &AsarEntry) -> io::Result<Vec<u8>> {
        if entry.unpacked {
            let unpacked_root = self.path.with_extension("asar.unpacked");
            let file_path = unpacked_root.join(&entry.path);
            std::fs::read(file_path)
        } else {
            let data_offset = 8 + self.header_size + entry.offset;
            let mut buf = vec![0u8; entry.size as usize];
            read_exact_at(&self.file, &mut buf, data_offset)?;
            Ok(buf)
        }
    }

    pub fn extract_all(
        &self,
        dest_dir: &Path,
        integrity_policy: IntegrityPolicy,
    ) -> Result<ExtractionResult, Box<dyn std::error::Error>> {
        fs::create_dir_all(dest_dir)?;
        let canonical_dest = dest_dir.canonicalize()?;

        let mut extracted_files = Vec::new();
        let mut contradictions = Vec::new();
        let mut total_bytes = 0u64;

        for entry in &self.entries {
            // Path traversal defense
            let rel_path = Path::new(&entry.path);
            for component in rel_path.components() {
                match component {
                    Component::Normal(_) => {}
                    _ => {
                        return Err(format!(
                            "Unsafe path traversal component in ASAR entry: {}",
                            entry.path
                        )
                        .into());
                    }
                }
            }

            let target_path = canonical_dest.join(rel_path);
            // Ensure target is strictly inside destination
            if !target_path.starts_with(&canonical_dest) {
                return Err(format!(
                    "Path traversal escape detected for entry: {}",
                    entry.path
                )
                .into());
            }

            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let bytes = self.read_file(entry)?;
            let observed_hash = format!("{:x}", Sha256::digest(&bytes));

            let mut integrity_verified = None;
            if let Some(integrity) = &entry.integrity {
                if let Some(expected_hash) = &integrity.hash {
                    if expected_hash.eq_ignore_ascii_case(&observed_hash) {
                        integrity_verified = Some(true);
                    } else {
                        integrity_verified = Some(false);
                        let contradiction = IntegrityContradiction {
                            path: entry.path.clone(),
                            expected_hash: expected_hash.clone(),
                            observed_hash: observed_hash.clone(),
                        };
                        match integrity_policy {
                            IntegrityPolicy::Fail => {
                                return Err(format!(
                                    "Integrity check failed for '{}': expected {}, observed {}",
                                    entry.path, expected_hash, observed_hash
                                )
                                .into());
                            }
                            IntegrityPolicy::RecordAndContinue => {
                                contradictions.push(contradiction);
                            }
                        }
                    }
                }
            }

            let mut out_file = File::create(&target_path)?;
            out_file.write_all(&bytes)?;

            #[cfg(unix)]
            if entry.executable {
                let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755));
            }

            total_bytes += bytes.len() as u64;
            extracted_files.push(ExtractedFile {
                path: entry.path.clone(),
                size: entry.size,
                sha256: observed_hash,
                integrity_verified,
            });
        }

        // ponytail: plain extraction; add symlink restoration when asar link fields are required.
        Ok(ExtractionResult {
            output_directory: canonical_dest.to_string_lossy().to_string(),
            total_files: extracted_files.len(),
            total_bytes,
            files: extracted_files,
            contradictions,
        })
    }
}

static EXTRACT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackResult {
    pub asar_path: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub asar_size: u64,
    pub sha256: String,
}

fn insert_file_node(
    files_map: &mut serde_json::Map<String, serde_json::Value>,
    components: &[&str],
    file_node: serde_json::Value,
) {
    if components.is_empty() {
        return;
    }
    if components.len() == 1 {
        files_map.insert(components[0].to_string(), file_node);
    } else {
        let dir_val = files_map
            .entry(components[0].to_string())
            .or_insert_with(|| serde_json::json!({ "files": {} }));
        if let Some(sub_files) = dir_val.get_mut("files").and_then(|v| v.as_object_mut()) {
            insert_file_node(sub_files, &components[1..], file_node);
        }
    }
}

pub fn pack_asar(src_dir: &Path, dest_asar: &Path) -> Result<PackResult, Box<dyn std::error::Error>> {
    let canonical_src = src_dir.canonicalize()?;
    if !canonical_src.is_dir() {
        return Err("Source path must be a directory".into());
    }

    let mut regular_files = Vec::new();
    for entry in ignore::WalkBuilder::new(&canonical_src)
        .hidden(false)
        .git_ignore(false)
        .require_git(false)
        .build()
    {
        let entry = entry?;
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            let rel = entry.path().strip_prefix(&canonical_src)?;
            regular_files.push(rel.to_path_buf());
        }
    }

    regular_files.sort();

    let mut root_files = serde_json::Map::new();
    let mut current_offset: u64 = 0;
    let mut total_bytes: u64 = 0;

    struct PackedFileInfo {
        rel_path: PathBuf,
        full_path: PathBuf,
        size: u64,
    }

    let mut files_to_write = Vec::new();

    for rel_path in &regular_files {
        let full_path = canonical_src.join(rel_path);
        let meta = fs::metadata(&full_path)?;
        let size = meta.len();
        let bytes = fs::read(&full_path)?;
        let hash = format!("{:x}", Sha256::digest(&bytes));

        let mut node = serde_json::json!({
            "size": size,
            "offset": current_offset.to_string(),
            "integrity": {
                "algorithm": "SHA256",
                "hash": hash
            }
        });

        #[cfg(unix)]
        if meta.permissions().mode() & 0o111 != 0 {
            if let Some(obj) = node.as_object_mut() {
                obj.insert("executable".to_string(), serde_json::Value::Bool(true));
            }
        }

        let comps: Vec<&str> = rel_path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();

        insert_file_node(&mut root_files, &comps, node);

        files_to_write.push(PackedFileInfo {
            rel_path: rel_path.clone(),
            full_path,
            size,
        });

        current_offset += size;
        total_bytes += size;
    }

    let root_json = serde_json::json!({ "files": root_files });
    let json_str = serde_json::to_string(&root_json)?;
    let json_bytes = json_str.as_bytes();
    let aligned_json = (json_bytes.len() + 3) / 4 * 4;
    let header_size = (8 + aligned_json) as u32;

    if let Some(parent) = dest_asar.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut out = File::create(dest_asar)?;
    out.write_all(&4u32.to_le_bytes())?;
    out.write_all(&header_size.to_le_bytes())?;
    out.write_all(&(header_size - 4).to_le_bytes())?;
    out.write_all(&(json_bytes.len() as u32).to_le_bytes())?;
    out.write_all(json_bytes)?;

    let padding_needed = (8 + header_size as usize).saturating_sub(16 + json_bytes.len());
    if padding_needed > 0 {
        out.write_all(&vec![0u8; padding_needed])?;
    }

    for f in &files_to_write {
        let file_bytes = fs::read(&f.full_path)?;
        out.write_all(&file_bytes)?;
    }
    out.flush()?;
    drop(out);

    let asar_bytes = fs::read(dest_asar)?;
    let asar_size = asar_bytes.len() as u64;
    let asar_sha256 = format!("{:x}", Sha256::digest(&asar_bytes));

    Ok(PackResult {
        asar_path: dest_asar.to_string_lossy().to_string(),
        total_files: files_to_write.len(),
        total_bytes,
        asar_size,
        sha256: asar_sha256,
    })
}

pub fn extract_artifact(
    archive_path: &Path,
    output_dir: Option<&Path>,
    integrity_policy: IntegrityPolicy,
) -> Result<ExtractionResult, Box<dyn std::error::Error>> {
    let archive = AsarArchive::open(archive_path)?;
    let dest = match output_dir {
        Some(p) => p.to_path_buf(),
        None => {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let count = EXTRACT_COUNTER.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!("rea_extracted_{}_{}_{}", std::process::id(), nanos, count))
        }
    };
    archive.extract_all(&dest, integrity_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_test_asar(json: &str, content: &[u8]) -> Vec<u8> {
        let text = json.as_bytes();
        let aligned_json = (text.len() + 3) / 4 * 4;
        let header_size = (8 + aligned_json) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&header_size.to_le_bytes());
        bytes.extend_from_slice(&(header_size - 4).to_le_bytes());
        bytes.extend_from_slice(&(text.len() as u32).to_le_bytes());
        bytes.extend_from_slice(text);
        while bytes.len() < (8 + header_size) as usize {
            bytes.push(0);
        }
        bytes.extend_from_slice(content);
        bytes
    }

    #[test]
    fn parses_asar_archive_and_reads_content() {
        let json = r#"{"files":{"hello.txt":{"size":5,"offset":"0"},"sub":{"files":{"world.js":{"size":13,"offset":"5"}}}}}"#;
        let content = b"helloconsole.log()";
        let asar_bytes = make_test_asar(json, content);

        let temp_dir = std::env::temp_dir();
        let test_asar_path = temp_dir.join("test_archive.asar");
        let mut f = File::create(&test_asar_path).unwrap();
        f.write_all(&asar_bytes).unwrap();
        drop(f);

        let archive = AsarArchive::open(&test_asar_path).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].path, "hello.txt");
        assert_eq!(archive.entries[0].size, 5);
        assert_eq!(archive.entries[1].path, "sub/world.js");
        assert_eq!(archive.entries[1].size, 13);

        let hello = archive.read_file(&archive.entries[0]).unwrap();
        assert_eq!(hello, b"hello");

        let world = archive.read_file(&archive.entries[1]).unwrap();
        assert_eq!(world, b"console.log()");

        let _ = std::fs::remove_file(test_asar_path);
    }

    #[test]
    fn extracts_all_with_integrity_and_contradictions() {
        let hello_hash = format!("{:x}", Sha256::digest(b"hello"));
        let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let json = format!(
            r#"{{"files":{{"valid.txt":{{"size":5,"offset":"0","integrity":{{"algorithm":"SHA256","hash":"{hello_hash}"}}}},"corrupt.txt":{{"size":5,"offset":"0","integrity":{{"algorithm":"SHA256","hash":"{bad_hash}"}}}}}}}}"#
        );
        let content = b"hello";
        let asar_bytes = make_test_asar(&json, content);

        let temp_dir = std::env::temp_dir();
        let test_asar_path = temp_dir.join("test_extract.asar");
        let mut f = File::create(&test_asar_path).unwrap();
        f.write_all(&asar_bytes).unwrap();
        drop(f);

        let archive = AsarArchive::open(&test_asar_path).unwrap();
        let dest_fail = temp_dir.join("test_extract_dest_fail");
        let dest_record = temp_dir.join("test_extract_dest_record");

        // Fail policy should reject
        let err = archive.extract_all(&dest_fail, IntegrityPolicy::Fail);
        assert!(err.is_err());

        // RecordAndContinue policy should succeed and record contradiction
        let res = archive.extract_all(&dest_record, IntegrityPolicy::RecordAndContinue).unwrap();
        assert_eq!(res.total_files, 2);
        assert_eq!(res.contradictions.len(), 1);
        assert_eq!(res.contradictions[0].path, "corrupt.txt");
        assert_eq!(res.contradictions[0].expected_hash, bad_hash);

        let extracted_valid = std::fs::read(dest_record.join("valid.txt")).unwrap();
        assert_eq!(extracted_valid, b"hello");

        let _ = std::fs::remove_file(test_asar_path);
        let _ = std::fs::remove_dir_all(dest_fail);
        let _ = std::fs::remove_dir_all(dest_record);
    }

    #[test]
    fn extract_artifact_creates_fresh_temp_dir() {
        let json = r#"{"files":{"app.js":{"size":4,"offset":"0"}}}"#;
        let content = b"1337";
        let asar_bytes = make_test_asar(json, content);

        let temp_dir = std::env::temp_dir();
        let test_asar_path = temp_dir.join("test_fresh_extract.asar");
        let mut f = File::create(&test_asar_path).unwrap();
        f.write_all(&asar_bytes).unwrap();
        drop(f);

        let res = extract_artifact(&test_asar_path, None, IntegrityPolicy::Fail).unwrap();
        assert_eq!(res.total_files, 1);
        let out_path = PathBuf::from(&res.output_directory);
        assert!(out_path.exists());
        assert_eq!(std::fs::read(out_path.join("app.js")).unwrap(), b"1337");

        let _ = std::fs::remove_file(test_asar_path);
        let _ = std::fs::remove_dir_all(out_path);
    }

    #[test]
    fn packs_and_unpacks_directory_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("rea_pack_test_{}", std::process::id()));
        let src_dir = temp_dir.join("src");
        let dest_asar = temp_dir.join("packed.asar");
        let extract_dir = temp_dir.join("unpacked");

        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(src_dir.join("nested")).unwrap();

        fs::write(src_dir.join("index.js"), b"console.log('root');").unwrap();
        fs::write(src_dir.join("nested/util.js"), b"function helper() { return 42; }").unwrap();

        let pack_res = pack_asar(&src_dir, &dest_asar).unwrap();
        assert_eq!(pack_res.total_files, 2);
        assert!(dest_asar.exists());

        let archive = AsarArchive::open(&dest_asar).unwrap();
        assert_eq!(archive.entries.len(), 2);

        let ext_res = archive.extract_all(&extract_dir, IntegrityPolicy::Fail).unwrap();
        assert_eq!(ext_res.total_files, 2);
        assert_eq!(ext_res.contradictions.len(), 0);

        assert_eq!(fs::read(extract_dir.join("index.js")).unwrap(), b"console.log('root');");
        assert_eq!(fs::read(extract_dir.join("nested/util.js")).unwrap(), b"function helper() { return 42; }");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
