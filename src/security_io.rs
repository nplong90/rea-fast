//! Resource-bounded input and fail-closed extraction output helpers.
//!
//! A catalog route is not allowed to turn an attacker-controlled artifact
//! into an unbounded allocation or silently overwrite an existing file.

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
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

/// Exclusive leaf creation for a caller-managed, already trusted parent.
/// Untrusted extraction paths must use `ExtractionRoot` instead.
pub fn create_new_file(path: &Path) -> io::Result<File> {
    File::options().write(true).create_new(true).open(path)
}

/// A directory capability held for the entire extraction. All output paths
/// are resolved relative to opened directory handles, so replacing a checked
/// directory with a symlink cannot redirect writes outside this root.
pub struct ExtractionRoot {
    directory: Dir,
}

impl ExtractionRoot {
    pub fn create(path: &Path) -> io::Result<Self> {
        create_private_output_directory(path)?;
        Ok(Self {
            directory: Dir::open_ambient_dir(path, ambient_authority())?,
        })
    }

    /// Atomically creates a new file beneath this root. Directory components
    /// are walked one handle at a time; none of the subsequent operations use
    /// absolute paths or re-open a directory via the process namespace.
    pub fn create_new_file(&self, relative: &Path) -> io::Result<cap_std::fs::File> {
        let mut components = relative.components().peekable();
        let mut current = self.directory.open_dir(".")?;
        loop {
            let Some(Component::Normal(name)) = components.next() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unsafe extraction path",
                ));
            };
            if components.peek().is_none() {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                return current.open_with(name, &options);
            }
            match current.create_dir(name) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            let meta = current.symlink_metadata(name)?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unsafe extraction parent",
                ));
            }
            current = current.open_dir(name)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    fn fresh_test_path(label: &str) -> PathBuf {
        static NONCE: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "rea-fast-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NONCE.fetch_add(1, Ordering::Relaxed),
        ))
    }

    #[cfg(unix)]
    fn link_directory(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn link_directory(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn unlink_directory_link(link: &Path) -> io::Result<()> {
        fs::remove_file(link)
    }

    #[cfg(windows)]
    fn unlink_directory_link(link: &Path) -> io::Result<()> {
        fs::remove_dir(link)
    }

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
        let output = ExtractionRoot::create(&base).unwrap();
        let path = base.join("a/b/file");
        output
            .create_new_file(Path::new("a/b/file"))
            .unwrap()
            .write_all(b"original")
            .unwrap();
        assert_eq!(
            output
                .create_new_file(Path::new("a/b/file"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(
            create_private_output_directory(&base).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            output
                .create_new_file(Path::new("a/../escape"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        // Windows does not permit removing a directory while an open Dir
        // handle still references it.
        drop(output);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn concurrent_directory_swap_cannot_escape_extraction_capability() {
        let base = fresh_test_path("race-root");
        let outside = fresh_test_path("race-outside");
        let output = ExtractionRoot::create(&base).unwrap();
        fs::create_dir(&outside).unwrap();
        let marker = outside.join("sentinel");
        fs::write(&marker, b"untouched").unwrap();

        let slot = base.join("slot");
        let held = base.join("slot-held");
        fs::create_dir(&slot).unwrap();

        // Force the dangerous path to exist at least once even if the
        // concurrent threads never happen to interleave on a busy runner.
        fs::rename(&slot, &held).unwrap();
        link_directory(&outside, &slot).expect("test requires directory-link support");
        assert!(output.create_new_file(Path::new("slot/forbidden")).is_err());
        unlink_directory_link(&slot).unwrap();
        fs::rename(&held, &slot).unwrap();

        let active = Arc::new(AtomicBool::new(true));
        let swaps = Arc::new(AtomicUsize::new(0));
        let writer_active = active.clone();
        let attacker_active = active.clone();
        let attacker_swaps = swaps.clone();
        let attacker = std::thread::spawn(move || {
            let mut counter = 0usize;
            while attacker_active.load(Ordering::Acquire) {
                // Do not rename a held directory back onto `slot`: the
                // defender may legitimately recreate `slot` meanwhile.
                let held = slot.with_file_name(format!("slot-held-{counter}"));
                counter += 1;
                if fs::rename(&slot, &held).is_ok() && link_directory(&outside, &slot).is_ok() {
                    attacker_swaps.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                    unlink_directory_link(&slot).unwrap();
                }
                std::thread::yield_now();
            }
            outside
        });
        let writer = std::thread::spawn(move || {
            for index in 0..600 {
                let relative = PathBuf::from(format!("slot/entry-{index}"));
                if let Ok(mut file) = output.create_new_file(&relative) {
                    file.write_all(b"safe").unwrap();
                }
                std::thread::yield_now();
            }
            writer_active.store(false, Ordering::Release);
        });

        writer.join().unwrap();
        let outside = attacker.join().unwrap();
        assert!(
            swaps.load(Ordering::Relaxed) > 0,
            "no concurrent swaps were exercised"
        );
        assert_eq!(fs::read(&marker).unwrap(), b"untouched");
        let outside_entries = fs::read_dir(&outside).unwrap().count();
        assert_eq!(
            outside_entries, 1,
            "extraction created files outside its root"
        );
        fs::remove_dir_all(&base).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn replacing_visible_root_after_open_cannot_redirect_writes() {
        let base = fresh_test_path("root-swap");
        let held = fresh_test_path("root-held");
        let outside = fresh_test_path("root-outside");
        let output = ExtractionRoot::create(&base).unwrap();
        fs::create_dir(&outside).unwrap();

        match fs::rename(&base, &held) {
            Ok(()) => {
                // On Unix the opened root remains usable after a rename.
                // On Windows directory handles may prevent the rename
                // entirely, which is also an acceptable containment result.
                link_directory(&outside, &base).expect("test requires directory-link support");
                let mut output_file = output.create_new_file(Path::new("safe.txt")).unwrap();
                output_file.write_all(b"inside").unwrap();
                drop(output_file);
                assert!(!outside.join("safe.txt").exists());
                assert_eq!(fs::read(held.join("safe.txt")).unwrap(), b"inside");
                unlink_directory_link(&base).unwrap();
                fs::rename(&held, &base).unwrap();
            }
            Err(error)
                if cfg!(windows)
                    && (error.kind() == io::ErrorKind::PermissionDenied
                        || error.raw_os_error() == Some(32)) =>
            {
                output.create_new_file(Path::new("safe.txt")).unwrap();
                assert!(!outside.join("safe.txt").exists());
            }
            Err(error) => panic!("cannot exercise root swap: {error}"),
        }

        drop(output);
        fs::remove_dir_all(&base).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }
}
