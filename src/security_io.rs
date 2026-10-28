//! Resource-bounded input and fail-closed extraction output helpers.
//!
//! A catalog route is not allowed to turn an attacker-controlled artifact
//! into an unbounded allocation or silently overwrite an existing file.

use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path},
};

pub const MAX_ANALYSIS_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub fn read_limited(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Input exceeds {limit} byte limit: {}", path.display()),
        ));
    }
    let mut content = Vec::new();
    file.take(limit + 1).read_to_end(&mut content)?;
    if content.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Input grew beyond {limit} byte limit: {}", path.display()),
        ));
    }
    Ok(content)
}

pub fn read_string_limited(path: &Path, limit: u64) -> io::Result<String> {
    String::from_utf8(read_limited(path, limit)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Creates a fresh, private output root. The caller must provide a new name;
/// existing directories and symlink leaves are never reused.
pub fn create_private_output_directory(output: &Path) -> io::Result<()> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Symlinked parent chains make lexical containment checks meaningless.
    for ancestor in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let md = fs::symlink_metadata(ancestor)?;
        if md.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Symlinked extraction parent: {}", ancestor.display()),
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(output)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(output)
    }
}

/// Creates only plain subdirectories below a newly created private root.
pub fn ensure_plain_parents(root: &Path, relative_parent: &Path) -> io::Result<()> {
    let root_canonical = root.canonicalize()?;
    let mut current = root_canonical.clone();
    for component in relative_parent.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsafe output path",
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unsafe output parent",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(e) => return Err(e),
        }
        if !current.canonicalize()?.starts_with(&root_canonical) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Output escaped root",
            ));
        }
    }
    Ok(())
}

pub fn create_new_file(path: &Path) -> io::Result<File> {
    File::options().write(true).create_new(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn refuses_input_beyond_limit_even_for_sparse_files() {
        let base = std::env::temp_dir().join(format!("rea-fast-limited-{}", std::process::id()));
        let _ = fs::remove_file(&base);
        let f = File::create(&base).unwrap();
        f.set_len(2048).unwrap();
        assert_eq!(
            read_limited(&base, 1024).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(&base).unwrap();
    }

    #[test]
    fn exclusive_outputs_never_clobber() {
        let base = std::env::temp_dir().join(format!("rea-fast-safe-out-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        create_private_output_directory(&base).unwrap();
        ensure_plain_parents(&base, Path::new("a/b")).unwrap();
        let path = base.join("a/b/file");
        create_new_file(&path)
            .unwrap()
            .write_all(b"original")
            .unwrap();
        assert_eq!(
            create_new_file(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(
            create_private_output_directory(&base).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_dir_all(&base).unwrap();
    }
}
