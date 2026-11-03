//! Keep the exact plaintext source open until the new encrypted index is committed.
//! Windows sharing restrictions prevent ordinary writers and replacement while held.
//! Unix locks are advisory: a noncooperating writer can still race the final hash,
//! overwrite, or unlink. The checks below reduce that risk, but do not make Unix
//! cleanup atomic against hostile writers. Callers must retain committed ciphertext
//! when cleanup fails, and must not fall back to deleting the source by pathname.

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::crypto::FileDigest;

pub(super) struct SourceGuard {
    file: File,
    path: PathBuf,
    verified: Option<FileDigest>,
}

pub(super) fn open(path: &Path) -> Result<SourceGuard> {
    ensure_plain_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ only.
        // OPEN_REPARSE_POINT ensures the final component is not followed.
        options
            .access_mode(0x8000_0000 | 0x4000_0000 | 0x0001_0000)
            .share_mode(0x0000_0001)
            .custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Cannot protect plaintext source '{}'", path.display()))?;
    #[cfg(unix)]
    file.try_lock()
        .with_context(|| format!("Cannot lock plaintext source '{}'", path.display()))?;
    #[cfg(not(any(windows, unix)))]
    anyhow::bail!("Incremental plaintext cleanup is unsupported on this platform");

    let guard = SourceGuard {
        file,
        path: path.to_path_buf(),
        verified: None,
    };
    guard.check_identity()?;
    Ok(guard)
}

fn ensure_plain_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Plaintext source is not a regular file: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x0000_0400 == 0,
            "Reparse-point plaintext sources are not supported: {}",
            path.display()
        );
    }
    ensure!(
        !metadata.permissions().readonly(),
        "Read-only plaintext source retained: {}",
        path.display()
    );
    Ok(())
}

impl SourceGuard {
    fn check_identity(&self) -> Result<()> {
        ensure_plain_file(&self.path)?;
        ensure!(
            self.file.metadata()?.is_file(),
            "Source handle is not a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = self.file.metadata()?;
            let current = fs::symlink_metadata(&self.path)?;
            ensure!(
                held.nlink() == 1 && current.nlink() == 1,
                "Hard-linked plaintext source retained: {}",
                self.path.display()
            );
            ensure!(
                !current.file_type().is_symlink()
                    && held.dev() == current.dev()
                    && held.ino() == current.ino(),
                "Plaintext source was replaced: {}",
                self.path.display()
            );
        }
        #[cfg(windows)]
        windows::check_identity(&self.file, &self.path)?;
        Ok(())
    }

    /// Verify the encrypted bytes match this still-protected source handle.
    /// A failed verification always revokes any earlier permission to erase.
    pub(super) fn verify(&mut self, digest: &FileDigest) -> Result<()> {
        self.verified = None;
        self.check_identity()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
        loop {
            let read = self.file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .context("Source size overflow")?;
            hasher.update(&buffer[..read]);
        }
        let hash: [u8; 32] = hasher.finalize().into();
        ensure!(
            size == digest.size && hash == digest.sha256,
            "Plaintext changed since encryption; source retained: {}",
            self.path.display()
        );
        self.check_identity()?;
        ensure!(
            self.file.metadata()?.len() == size,
            "Plaintext size changed during verification"
        );
        self.verified = Some(digest.clone());
        Ok(())
    }

    /// Invoke only AFTER publishing durable ciphertext and its authenticated index.
    /// Never reopen the source for writing: overwrite and Windows deletion use the
    /// same held handle. SSD/COW storage can retain old blocks despite overwriting.
    pub(super) fn erase(mut self) -> Result<()> {
        let digest = self
            .verified
            .clone()
            .context("Source was not verified for erasure")?;
        // Catch changes by noncooperating Unix writers between verify and commit.
        self.verify(&digest)?;
        self.file.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; 8192];
        let mut remaining = digest.size;
        while remaining > 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            self.file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        self.file.sync_all()?;
        #[cfg(windows)]
        windows::delete_held_file(&self.file)?;
        #[cfg(unix)]
        {
            self.check_identity()?;
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct FileInformation {
        attributes: u32,
        creation_time: [u32; 2],
        access_time: [u32; 2],
        write_time: [u32; 2],
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInformation) -> i32;
        fn SetFileInformationByHandle(
            handle: *mut c_void,
            class: i32,
            info: *const c_void,
            size: u32,
        ) -> i32;
    }

    fn information(file: &File) -> Result<FileInformation> {
        let mut info = FileInformation::default();
        // SAFETY: handle stays live for the call; info is a correctly sized writable
        // BY_HANDLE_FILE_INFORMATION structure with the documented C layout.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(
            info.attributes & 0x400 == 0,
            "Reparse-point source handle rejected"
        );
        ensure!(info.links == 1, "Hard-linked plaintext source retained");
        Ok(info)
    }

    pub(super) fn check_identity(file: &File, path: &Path) -> Result<()> {
        let current = OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2 | 0x4)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let held = information(file)?;
        let named = information(&current)?;
        ensure!(
            (held.volume_serial, held.index_high, held.index_low)
                == (named.volume_serial, named.index_high, named.index_low),
            "Plaintext source was replaced: {}",
            path.display()
        );
        Ok(())
    }

    pub(super) fn delete_held_file(file: &File) -> Result<()> {
        // FILE_DISPOSITION_INFO contains a single BOOLEAN (one byte).
        let delete_file: u8 = 1;
        // SAFETY: live DELETE-capable handle; class 4 is FileDispositionInfo;
        // buffer points to the documented one-byte structure for the call.
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                4,
                (&delete_file as *const u8).cast(),
                1,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("securevault_source_guard_{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn digest(bytes: &[u8]) -> crate::crypto::FileDigest {
        crate::crypto::FileDigest {
            size: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    #[test]
    fn digest_mismatch_prevents_erasure_and_preserves_plaintext() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        fs::write(&path, b"new content").unwrap();
        let mut guard = open(&path).unwrap();
        assert!(guard.verify(&digest(b"old content")).is_err());
        assert!(guard.erase().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"new content");
    }

    #[test]
    fn matching_digest_allows_erasure() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        fs::write(&path, b"original content").unwrap();
        let mut guard = open(&path).unwrap();
        guard.verify(&digest(b"original content")).unwrap();
        guard.erase().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn erasure_without_verification_is_rejected() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        fs::write(&path, b"original content").unwrap();
        assert!(open(&path).unwrap().erase().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original content");
    }

    #[test]
    fn failed_verification_revokes_previous_success() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        fs::write(&path, b"original content").unwrap();
        let mut guard = open(&path).unwrap();
        guard.verify(&digest(b"original content")).unwrap();
        assert!(guard.verify(&digest(b"wrong content")).is_err());
        assert!(guard.erase().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original content");
    }

    #[test]
    fn hardlinked_source_is_rejected_without_modifying_either_name() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        let alias = dir.0.join("other-name.txt");
        fs::write(&path, b"shared original content").unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(open(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"shared original content");
        assert_eq!(fs::read(&alias).unwrap(), b"shared original content");
    }

    #[cfg(windows)]
    #[test]
    fn windows_guard_allows_reading_but_blocks_writing_and_replacement() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        let other = dir.0.join("replacement.txt");
        fs::write(&path, b"original content").unwrap();
        fs::write(&other, b"replacement").unwrap();
        let guard = open(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"original content");
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::rename(&other, &path).is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(guard);
        assert_eq!(fs::read(&path).unwrap(), b"original content");
    }

    #[cfg(unix)]
    #[test]
    fn unix_replaced_path_is_not_erased() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        let original = dir.0.join("moved.txt");
        fs::write(&path, b"original content").unwrap();
        let mut guard = open(&path).unwrap();
        guard.verify(&digest(b"original content")).unwrap();
        fs::rename(&path, &original).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(guard.erase().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::read(&original).unwrap(), b"original content");
    }

    #[cfg(unix)]
    #[test]
    fn unix_noncooperating_write_is_detected_before_erasure() {
        let dir = TestDir::new();
        let path = dir.0.join("source.txt");
        fs::write(&path, b"original content").unwrap();
        let mut guard = open(&path).unwrap();
        guard.verify(&digest(b"original content")).unwrap();
        fs::write(&path, b"changed content").unwrap();
        assert!(guard.erase().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"changed content");
    }
}
