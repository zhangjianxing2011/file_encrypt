use anyhow::{Context, Result};
use std::path::Path;

/// Replace metadata with an already flushed temporary file on the same filesystem.
///
/// The caller owns flushing the temporary file and syncing the parent directory.
/// An `Ok` result means replacement has happened; deliberately do not perform any
/// fallible work after the replacement, so the caller can track its commit boundary.
pub(super) fn replace_synced(temp: &Path, target: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        }

        fn wide_path(path: &Path) -> Result<Vec<u16>> {
            let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
            anyhow::ensure!(!encoded.contains(&0), "Path contains an embedded NUL");
            encoded.push(0);
            Ok(encoded)
        }

        let source = wide_path(temp)?;
        let destination = wide_path(target)?;
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
        // COPY_ALLOWED is intentionally absent: cross-volume copies must not be
        // substituted for a same-volume metadata replacement.
        let replaced = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("Cannot replace metadata file '{}'", target.display()));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        std::fs::rename(temp, target)
            .with_context(|| format!("Cannot replace metadata file '{}'", target.display()))
    }
}

/// Persist directory-entry changes on Unix.
///
/// Windows has no portable equivalent of directory fsync through `std`.
/// On Windows this is intentionally a no-op: callers must flush every file and
/// use the write-through replacement above, without claiming Unix-equivalent
/// directory crash durability. Filesystem/device guarantees still apply.
pub(super) fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)
            .with_context(|| {
                format!(
                    "Cannot open directory for synchronization '{}'",
                    path.display()
                )
            })?
            .sync_all()
            .with_context(|| format!("Cannot synchronize directory '{}'", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "securevault_metadata_replace_{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_synced(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn replaces_existing_metadata_and_consumes_temporary_file() {
        let dir = TestDir::new();
        let target = dir.0.join("metadata");
        let temp = dir.0.join("metadata.tmp");
        write_synced(&target, b"old index");
        write_synced(&temp, b"new index");

        replace_synced(&temp, &target).unwrap();
        sync_dir(&dir.0).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new index");
        assert!(!temp.exists());
    }

    #[test]
    fn installs_metadata_when_target_does_not_exist() {
        let dir = TestDir::new();
        let target = dir.0.join("metadata");
        let temp = dir.0.join("metadata.tmp");
        write_synced(&temp, b"first index");

        replace_synced(&temp, &target).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"first index");
        assert!(!temp.exists());
    }

    #[test]
    fn missing_temporary_file_does_not_destroy_existing_metadata() {
        let dir = TestDir::new();
        let target = dir.0.join("metadata");
        write_synced(&target, b"original index");

        assert!(replace_synced(&dir.0.join("missing.tmp"), &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original index");
    }
}
