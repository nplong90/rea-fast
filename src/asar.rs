use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
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
const MAX_ASAR_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// All ASAR paths should be safe to extract on both Unix and Windows,
/// regardless of the host platform that originally packaged the archive.
fn portable_asar_component(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("");
    let windows_reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(':')
        && !name.chars().any(char::is_control)
        && !name.ends_with('.')
        && !name.ends_with(' ')
        && !windows_reserved
            .iter()
            .any(|word| stem.eq_ignore_ascii_case(word))
}

/// Reject symlinks anywhere below the selected extraction root. Lexical path
/// containment alone does not prevent an existing `subdir` symlink from
/// redirecting writes outside that root.
fn ensure_plain_subdirectories(root: &Path, rel_parent: &Path) -> io::Result<()> {
    let mut current = root.to_path_buf();
    for component in rel_parent.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe ASAR parent path",
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "ASAR extraction parent is not a plain directory: {}",
                        current.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error),
        }
    }
    if current.canonicalize()? != current {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ASAR extraction parent resolves through a symlink",
        ));
    }
    Ok(())
}

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
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF",
                ));
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
        let payload_size =
            u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as u64;
        let json_len = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]) as u64;

        if size_payload != 4
            || header_size < 8
            || payload_size != header_size - 4
            || json_len > payload_size - 4
        {
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
        let first_non_ws = json_bytes
            .iter()
            .find(|&&b| !matches!(b, 0x20 | 0x09 | 0x0a | 0x0d));
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
            if !portable_asar_component(&name) {
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
                    Some(AsarOffset::Str(s)) => s.parse::<u64>().map_err(|_| {
                        format!("ASAR entry has invalid numeric data offset: {path}")
                    })?,
                    Some(AsarOffset::Num(n)) => n,
                    None if node.unpacked.unwrap_or(false) => 0,
                    None => return Err(format!("ASAR entry has no data offset: {path}").into()),
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
        if entry.size > MAX_ASAR_ENTRY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ASAR entry exceeds 64 MiB in-memory read limit",
            ));
        }
        if entry.unpacked {
            let unpacked_root = self.path.with_extension("asar.unpacked");
            let file_path = unpacked_root.join(&entry.path);
            if fs::symlink_metadata(&unpacked_root)?
                .file_type()
                .is_symlink()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ASAR unpacked root must not be a symlink",
                ));
            }
            // A simple symlinked asset can escape the unpacked sibling tree.
            let root = unpacked_root.canonicalize()?;
            let parent = Path::new(&entry.path)
                .parent()
                .unwrap_or_else(|| Path::new(""));
            let mut current = root.clone();
            for component in parent.components() {
                let Component::Normal(name) = component else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsafe unpacked path",
                    ));
                };
                current.push(name);
                if fs::symlink_metadata(&current)?.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "symlinked ASAR unpacked parent",
                    ));
                }
            }
            if !fs::symlink_metadata(&file_path)?.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ASAR unpacked member must be a plain regular file",
                ));
            }
            let file = File::open(file_path)?;
            if file.metadata()?.len() > MAX_ASAR_ENTRY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unpacked ASAR file exceeds 64 MiB limit",
                ));
            }
            use io::Read;
            let mut buffer = Vec::with_capacity(entry.size as usize);
            file.take(MAX_ASAR_ENTRY_BYTES + 1)
                .read_to_end(&mut buffer)?;
            if buffer.len() as u64 > MAX_ASAR_ENTRY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unpacked ASAR file grew beyond 64 MiB limit",
                ));
            }
            Ok(buffer)
        } else {
            let data_offset = 8u64
                .checked_add(self.header_size)
                .and_then(|offset| offset.checked_add(entry.offset))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "ASAR data offset overflow")
                })?;
            let end = data_offset.checked_add(entry.size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ASAR data extent overflow")
            })?;
            if end > self.file.metadata()?.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ASAR entry extends past archive end",
                ));
            }
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
        // Never reuse a caller-supplied directory: doing so would allow an
        // attacker to replace a checked child parent with a symlink while
        // extraction proceeds. The exclusive root is private on Unix.
        crate::security_io::create_private_output_directory(dest_dir)?;
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
                return Err(
                    format!("Path traversal escape detected for entry: {}", entry.path).into(),
                );
            }

            let rel_parent = rel_path.parent().unwrap_or_else(|| Path::new(""));
            ensure_plain_subdirectories(&canonical_dest, rel_parent)?;

            let bytes = self.read_file(entry)?;
            let observed_hash = format!("{:x}", Sha256::digest(&bytes));

            let mut integrity_verified = None;
            if let Some(integrity) = &entry.integrity
                && let Some(expected_hash) = &integrity.hash
            {
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

            // Exclusive creation refuses existing files and leaf symlinks;
            // extraction must never truncate a pre-existing user file.
            let mut out_file = File::options()
                .write(true)
                .create_new(true)
                .open(&target_path)?;
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
static PACK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hash or copy a file using a fixed-size buffer. The second pass must match
/// the first pass byte-for-byte before the generated archive is published.
fn stream_file_digest(
    path: &Path,
    mut destination: Option<&mut File>,
) -> io::Result<(u64, String)> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "ASAR source must not be a symlink or special file: {}",
                path.display()
            ),
        ));
    }
    let mut source = File::open(path)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("ASAR source is not a regular file: {}", path.display()),
        ));
    }

    let mut digest = Sha256::new();
    let mut total_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "ASAR source size overflow")
        })?;
        digest.update(&buffer[..count]);
        if let Some(output) = destination.as_mut() {
            output.write_all(&buffer[..count])?;
        }
    }
    Ok((total_bytes, format!("{:x}", digest.finalize())))
}

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

pub fn pack_asar(
    src_dir: &Path,
    dest_asar: &Path,
) -> Result<PackResult, Box<dyn std::error::Error>> {
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
    let mut files_to_write = Vec::new();

    for rel_path in &regular_files {
        let full_path = canonical_src.join(rel_path);
        #[cfg(unix)]
        let meta = fs::metadata(&full_path)?;
        let (size, hash) = stream_file_digest(&full_path, None)?;

        let node = serde_json::json!({
            "size": size,
            "offset": current_offset.to_string(),
            "integrity": {
                "algorithm": "SHA256",
                "hash": hash
            }
        });

        #[cfg(unix)]
        let mut node = node;
        #[cfg(unix)]
        if meta.permissions().mode() & 0o111 != 0
            && let Some(obj) = node.as_object_mut()
        {
            obj.insert("executable".to_string(), serde_json::Value::Bool(true));
        }

        let comps: Vec<&str> = rel_path
            .components()
            .map(|component| match component {
                Component::Normal(name) => name.to_str().ok_or_else(|| {
                    format!(
                        "ASAR cannot represent a non-UTF-8 path: {}",
                        rel_path.display()
                    )
                }),
                _ => Err(format!(
                    "ASAR source has an unsafe path: {}",
                    rel_path.display()
                )),
            })
            .collect::<Result<_, _>>()?;

        if comps.iter().any(|name| !portable_asar_component(name)) {
            return Err(format!(
                "ASAR source contains a non-portable path: {}",
                rel_path.display()
            )
            .into());
        }
        insert_file_node(&mut root_files, &comps, node);

        files_to_write.push((full_path, size, hash));

        current_offset = current_offset
            .checked_add(size)
            .ok_or("ASAR offset overflow")?;
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or("ASAR total size overflow")?;
    }

    let root_json = serde_json::json!({ "files": root_files });
    let json_str = serde_json::to_string(&root_json)?;
    let json_bytes = json_str.as_bytes();
    let aligned_json = json_bytes
        .len()
        .div_ceil(4)
        .checked_mul(4)
        .ok_or("ASAR header overflow")?;
    let header_size = u32::try_from(
        8usize
            .checked_add(aligned_json)
            .ok_or("ASAR header overflow")?,
    )?;
    let json_len = u32::try_from(json_bytes.len())?;

    let parent = dest_asar
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = dest_asar
        .file_name()
        .ok_or("ASAR destination needs a file name")?;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let temp_path = parent.join(format!(
        ".{}.rea-fast-{}-{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        nanos,
        PACK_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let mut out = File::options()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    let output_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        out.write_all(&4u32.to_le_bytes())?;
        out.write_all(&header_size.to_le_bytes())?;
        out.write_all(&(header_size - 4).to_le_bytes())?;
        out.write_all(&json_len.to_le_bytes())?;
        out.write_all(json_bytes)?;
        let padding_needed = (8 + header_size as usize).saturating_sub(16 + json_bytes.len());
        if padding_needed > 0 {
            out.write_all(&vec![0u8; padding_needed])?;
        }

        // Re-check every file's length and digest while copying. If the source
        // changed, do not publish an archive whose header claims stale hashes.
        for (f, expected_size, expected_hash) in &files_to_write {
            let (observed_size, observed_hash) = stream_file_digest(f, Some(&mut out))?;
            if observed_size != *expected_size || observed_hash != *expected_hash {
                return Err(format!("ASAR source changed during packing: {}", f.display()).into());
            }
        }
        out.flush()?;
        out.sync_all()?;
        Ok(())
    })();
    drop(out);
    if let Err(error) = output_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }

    let (asar_size, asar_sha256) = match stream_file_digest(&temp_path, None) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            return Err(error.into());
        }
    };
    // Create the final name atomically and refuse any pre-existing destination.
    // The staging file lives beside the destination, so hard_link is same-FS.
    let published = fs::hard_link(&temp_path, dest_asar);
    let _ = fs::remove_file(&temp_path);
    published?;

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
            std::env::temp_dir().join(format!(
                "rea_extracted_{}_{}_{}",
                std::process::id(),
                nanos,
                count
            ))
        }
    };
    archive.extract_all(&dest, integrity_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn isolated_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rea_asar_security_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn oversized_and_out_of_bounds_asar_entries_are_rejected_without_allocation() {
        let scope = isolated_test_dir();
        let archive_path = scope.join("input.asar");
        fs::write(
            &archive_path,
            make_test_asar(
                r#"{"files":{"large.bin":{"size":67108865,"offset":"0"}}}"#,
                b"",
            ),
        )
        .unwrap();
        let archive = AsarArchive::open(&archive_path).unwrap();
        assert!(archive.read_file(&archive.entries[0]).is_err());

        fs::write(
            &archive_path,
            make_test_asar(
                r#"{"files":{"bad.bin":{"size":5,"offset":"18446744073709551615"}}}"#,
                b"hello",
            ),
        )
        .unwrap();
        let archive = AsarArchive::open(&archive_path).unwrap();
        assert!(archive.read_file(&archive.entries[0]).is_err());

        fs::write(
            &archive_path,
            make_test_asar(
                r#"{"files":{"bad.bin":{"size":5,"offset":"not-an-offset"}}}"#,
                b"hello",
            ),
        )
        .unwrap();
        assert!(AsarArchive::open(&archive_path).is_err());
        fs::remove_dir_all(scope).unwrap();
    }

    #[test]
    fn extraction_refuses_to_overwrite_existing_file() {
        let scope = isolated_test_dir();
        let archive_path = scope.join("input.asar");
        let dest = scope.join("destination");
        fs::create_dir(&dest).unwrap();
        fs::write(
            &archive_path,
            make_test_asar(
                r#"{"files":{"existing.txt":{"size":5,"offset":"0"}}}"#,
                b"hello",
            ),
        )
        .unwrap();
        fs::write(dest.join("existing.txt"), b"personal content").unwrap();
        let archive = AsarArchive::open(&archive_path).unwrap();
        assert!(archive.extract_all(&dest, IntegrityPolicy::Fail).is_err());
        assert_eq!(
            fs::read(dest.join("existing.txt")).unwrap(),
            b"personal content"
        );
        fs::remove_dir_all(scope).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn extraction_rejects_symlinked_parent_and_output_file() {
        use std::os::unix::fs::symlink;

        let scope = isolated_test_dir();
        let archive_path = scope.join("input.asar");
        let dest = scope.join("destination");
        let outside = scope.join("outside");
        fs::create_dir(&dest).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(
            &archive_path,
            make_test_asar(
                r#"{"files":{"sub":{"files":{"escape.txt":{"size":5,"offset":"0"}}}}}"#,
                b"hello",
            ),
        )
        .unwrap();
        let archive = AsarArchive::open(&archive_path).unwrap();

        symlink(&outside, dest.join("sub")).unwrap();
        assert!(archive.extract_all(&dest, IntegrityPolicy::Fail).is_err());
        assert!(!outside.join("escape.txt").exists());

        fs::remove_file(dest.join("sub")).unwrap();
        fs::create_dir(dest.join("sub")).unwrap();
        fs::write(outside.join("victim.txt"), b"do not alter").unwrap();
        symlink(outside.join("victim.txt"), dest.join("sub/escape.txt")).unwrap();
        assert!(archive.extract_all(&dest, IntegrityPolicy::Fail).is_err());
        assert_eq!(
            fs::read(outside.join("victim.txt")).unwrap(),
            b"do not alter"
        );
        fs::remove_dir_all(scope).unwrap();
    }

    #[test]
    fn packing_never_overwrites_existing_archive() {
        let scope = isolated_test_dir();
        let source = scope.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("index.js"), b"console.log('hello')").unwrap();
        let target = scope.join("packed.asar");
        fs::write(&target, b"personal content").unwrap();

        assert!(pack_asar(&source, &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"personal content");
        assert_eq!(fs::read_dir(&scope).unwrap().count(), 2);
        fs::remove_dir_all(scope).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn packing_rejects_non_utf8_names_instead_of_silently_omitting_them() {
        use std::os::unix::ffi::OsStringExt;

        let scope = isolated_test_dir();
        let source = scope.join("source");
        fs::create_dir(&source).unwrap();
        let invalid_name = std::ffi::OsString::from_vec(vec![b'a', 0xff]);
        fs::write(source.join(invalid_name), b"unrepresentable").unwrap();
        let target = scope.join("packed.asar");

        assert!(pack_asar(&source, &target).is_err());
        assert!(!target.exists());
        fs::remove_dir_all(scope).unwrap();
    }

    #[test]
    fn streaming_packer_handles_file_larger_than_member_read_limit() {
        let scope = isolated_test_dir();
        let source = scope.join("source");
        fs::create_dir(&source).unwrap();
        let big_file = source.join("large.bin");
        File::create(&big_file)
            .unwrap()
            .set_len(MAX_ASAR_ENTRY_BYTES + 1)
            .unwrap();
        let target = scope.join("packed.asar");

        let result = pack_asar(&source, &target).unwrap();
        assert_eq!(result.total_files, 1);
        assert_eq!(result.total_bytes, MAX_ASAR_ENTRY_BYTES + 1);
        assert_eq!(fs::metadata(&target).unwrap().len(), result.asar_size);
        assert_eq!(stream_file_digest(&target, None).unwrap().1, result.sha256);

        let archive = AsarArchive::open(&target).unwrap();
        assert_eq!(archive.entries[0].size, MAX_ASAR_ENTRY_BYTES + 1);
        assert!(archive.read_file(&archive.entries[0]).is_err());
        fs::remove_dir_all(scope).unwrap();
    }

    fn make_test_asar(json: &str, content: &[u8]) -> Vec<u8> {
        let text = json.as_bytes();
        let aligned_json = text.len().div_ceil(4) * 4;
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
    fn asar_rejects_cross_platform_reserved_path_components() {
        let scope = isolated_test_dir();
        let file = scope.join("malicious.asar");
        for name in [
            r"sub\\file.txt",
            "C:drive.txt",
            "CON.txt",
            "lpt9.log",
            "trailing.",
            "trailing ",
            "new\nline",
        ] {
            let header = serde_json::json!({
                "files": {(name): {"size": 1, "offset": "0"}}
            });
            fs::write(&file, make_test_asar(&header.to_string(), b"x")).unwrap();
            assert!(AsarArchive::open(&file).is_err(), "unsafe name: {name}");
        }
        fs::remove_dir_all(scope).unwrap();
    }

    #[test]
    fn deterministic_asar_header_mutations_never_panic() {
        let scope = isolated_test_dir();
        let archive_path = scope.join("mutated.asar");
        let original = make_test_asar(
            r#"{"files":{"main.js":{"size":5,"offset":"0"},"lib":{"files":{"api.js":{"size":3,"offset":"5"}}}}}"#,
            b"helloapi",
        );
        // Seeded mutation corpus: corrupt Pickle extents, JSON bytes, entry
        // offsets and archive payload. A rejection is fine; panic is not.
        let mut seed = 0x6a09_e667_f3bc_c909u64;
        for case in 0..512 {
            let mut sample = original.clone();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let index = (seed as usize) % sample.len();
            sample[index] ^= ((case % 251) + 1) as u8;
            if case % 7 == 0 {
                sample.truncate((seed as usize) % sample.len());
            }
            fs::write(&archive_path, &sample).unwrap();
            if let Ok(archive) = AsarArchive::open(&archive_path) {
                for entry in &archive.entries {
                    let _ = archive.read_file(entry);
                }
            }
        }
        fs::remove_dir_all(scope).unwrap();
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
        let res = archive
            .extract_all(&dest_record, IntegrityPolicy::RecordAndContinue)
            .unwrap();
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
        fs::write(
            src_dir.join("nested/util.js"),
            b"function helper() { return 42; }",
        )
        .unwrap();

        let pack_res = pack_asar(&src_dir, &dest_asar).unwrap();
        assert_eq!(pack_res.total_files, 2);
        assert!(dest_asar.exists());

        let archive = AsarArchive::open(&dest_asar).unwrap();
        assert_eq!(archive.entries.len(), 2);

        let ext_res = archive
            .extract_all(&extract_dir, IntegrityPolicy::Fail)
            .unwrap();
        assert_eq!(ext_res.total_files, 2);
        assert_eq!(ext_res.contradictions.len(), 0);

        assert_eq!(
            fs::read(extract_dir.join("index.js")).unwrap(),
            b"console.log('root');"
        );
        assert_eq!(
            fs::read(extract_dir.join("nested/util.js")).unwrap(),
            b"function helper() { return 42; }"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
