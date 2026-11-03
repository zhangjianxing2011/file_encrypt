use crate::crypto::{CryptoEngine, DEFAULT_CHUNK_SIZE};
use crate::index::*;
use anyhow::{bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use uuid::Uuid;
use walkdir::WalkDir;

// ─── Public API ─────────────────────────────────────────────────────

/// Encrypt and lock a folder in-place.
///
/// 1. Scans all files and directories
/// 2. Encrypts each file → .vault_data/{uuid}.enc  (originals untouched)
/// 3. Writes encrypted index → .vault_meta
/// 4. Deletes original files and empty directories
pub fn lock(folder: &Path, password: &str) -> Result<()> {
    let folder = dunce_canonicalize(folder)?;

    ensure!(
        folder.is_dir(),
        "Path is not a directory: {}",
        folder.display()
    );
    ensure!(
        !is_locked(&folder),
        "Folder is already locked (found {})",
        VAULT_META_FILE
    );

    println!("🔐 Locking folder: {}", folder.display());

    // ── 1. Scan ─────────────────────────────────────────────────
    let (files, dirs) = scan_folder(&folder)?;
    if files.is_empty() {
        println!("📁 Folder is empty — nothing to encrypt.");
        return Ok(());
    }
    println!(
        "📊 Found {} file(s) in {} director(ies)",
        files.len(),
        dirs.len() + 1
    );

    // ── 2. Derive keys ──────────────────────────────────────────
    println!("🔑 Deriving encryption key (this may take a moment)...");
    let salt = CryptoEngine::generate_salt();
    let crypto = CryptoEngine::new(password.as_bytes(), &salt, DEFAULT_CHUNK_SIZE)?;

    // ── 3. Prepare vault_data directory ─────────────────────────
    let vault_data = folder.join(VAULT_DATA_DIR);
    if vault_data.exists() {
        println!("⚠️  Found leftover .vault_data from a previous attempt — removing...");
        fs::remove_dir_all(&vault_data)?;
    }
    fs::create_dir_all(&vault_data)?;

    // ── 4. Encrypt files in parallel ────────────────────────────
    let pb = make_progress_bar(files.len() as u64, "Encrypting", "cyan");
    let entries: Mutex<Vec<FileEntry>> = Mutex::new(Vec::with_capacity(files.len()));
    let errors: Mutex<Vec<(PathBuf, anyhow::Error)>> = Mutex::new(Vec::new());

    files.par_iter().for_each(|file_path| {
        let id = Uuid::new_v4().to_string();
        let enc_path = vault_data.join(format!("{}.enc", id));

        match crypto.encrypt_file(file_path, &enc_path) {
            Ok(()) => {
                if let Ok(entry) = build_file_entry(&id, file_path, &folder) {
                    entries.lock().unwrap().push(entry);
                }
            }
            Err(e) => {
                errors.lock().unwrap().push((file_path.clone(), e));
            }
        }
        pb.inc(1);
    });
    pb.finish_with_message("done");

    // Check for encryption errors — abort if any
    let errors = errors.into_inner().unwrap();
    if !errors.is_empty() {
        let _ = fs::remove_dir_all(&vault_data);
        for (path, err) in &errors {
            eprintln!("  ❌ {}: {}", path.display(), err);
        }
        bail!("Encryption failed for {} file(s) — aborted", errors.len());
    }

    // ── 5. Build and encrypt index ──────────────────────────────
    let file_entries = entries.into_inner().unwrap();
    let dir_entries = build_dir_entries(&folder, &dirs)?;

    let index = VaultIndex {
        version: 1,
        files: file_entries,
        dirs: dir_entries,
    };
    let index_json = serde_json::to_vec(&index)?;
    let encrypted_index = crypto.encrypt_index(&index_json)?;

    // ── 6. Write vault metadata ─────────────────────────────────
    let meta = VaultMeta {
        version: 1,
        salt: BASE64.encode(&salt),
        password_check: BASE64.encode(crypto.password_check()),
        chunk_size: DEFAULT_CHUNK_SIZE as u32,
        encrypted_index: BASE64.encode(&encrypted_index),
    };
    let meta_json = serde_json::to_string_pretty(&meta)?;
    fs::write(folder.join(VAULT_META_FILE), &meta_json)?;
    // Automatic disaster recovery backup inside .vault_data/
    let _ = fs::write(vault_data.join(VAULT_META_BACKUP_FILE), &meta_json);

    // ── 7. Delete originals ─────────────────────────────────────
    let pb = make_progress_bar(files.len() as u64, "Cleaning up", "red");
    for file_path in &files {
        if let Err(e) = secure_delete(file_path) {
            eprintln!("  ⚠️  Could not delete {}: {}", file_path.display(), e);
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    // Remove emptied directories (deepest first)
    remove_empty_dirs(&folder)?;

    // Hide vault files on Windows
    #[cfg(windows)]
    {
        let _ = set_hidden_attribute(&vault_data);
        let _ = set_hidden_attribute(&folder.join(VAULT_META_FILE));
    }

    let total_size: u64 = index.files.iter().map(|f| f.size).sum();
    println!(
        "✅ Locked! {} file(s), {} encrypted.",
        index.files.len(),
        format_size(total_size)
    );
    Ok(())
}

/// Decrypt and unlock a locked folder.
///
/// 1. Reads .vault_meta and verifies password
/// 2. Decrypts index to learn original file paths
/// 3. Recreates directory structure
/// 4. Decrypts each file back to its original location
/// 5. Removes .vault_data and .vault_meta
pub fn unlock(folder: &Path, password: &str) -> Result<()> {
    let folder = dunce_canonicalize(folder)?;

    ensure!(
        folder.is_dir(),
        "Path is not a directory: {}",
        folder.display()
    );
    ensure!(is_locked(&folder), "Folder is not locked (no {} found)", VAULT_META_FILE);

    println!("🔓 Unlocking folder: {}", folder.display());

    // ── 1. Read metadata (with auto-disaster recovery from backup) ─
    let (meta, meta_path) = read_vault_meta(&folder)?;
    let salt = BASE64.decode(&meta.salt)?;
    let password_check = BASE64.decode(&meta.password_check)?;

    // ── 2. Verify password ──────────────────────────────────────
    println!("🔑 Verifying password...");
    let crypto = CryptoEngine::new(password.as_bytes(), &salt, meta.chunk_size as usize)?;

    if !crypto.verify_password(&password_check) {
        bail!("❌ Incorrect password");
    }

    // ── 3. Decrypt index ────────────────────────────────────────
    let encrypted_index = BASE64.decode(&meta.encrypted_index)?;
    let index_json = crypto.decrypt_index(&encrypted_index)?;
    let index: VaultIndex = serde_json::from_slice(&index_json)?;

    println!(
        "📊 Restoring {} file(s), {} director(ies)",
        index.files.len(),
        index.dirs.len()
    );

    // ── 4. Recreate directories ─────────────────────────────────
    // Sort by depth (shallowest first) to create parents before children
    let mut sorted_dirs = index.dirs.clone();
    sorted_dirs.sort_by_key(|d| d.path.matches('/').count());

    for dir in &sorted_dirs {
        let dir_path = folder.join(&dir.path);
        fs::create_dir_all(&dir_path)?;

        #[cfg(unix)]
        if let Some(mode) = dir.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir_path, fs::Permissions::from_mode(mode));
        }
    }

    // ── 5. Decrypt files in parallel ────────────────────────────
    let vault_data = folder.join(VAULT_DATA_DIR);
    let pb = make_progress_bar(index.files.len() as u64, "Decrypting", "green");
    let errors: Mutex<Vec<(String, anyhow::Error)>> = Mutex::new(Vec::new());

    index.files.par_iter().for_each(|entry| {
        let enc_path = vault_data.join(format!("{}.enc", entry.id));
        let dst_path = folder.join(&entry.path);

        // Ensure parent dir exists
        if let Some(parent) = dst_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match crypto.decrypt_file(&enc_path, &dst_path) {
            Ok(()) => {
                restore_file_metadata(&dst_path, entry);
            }
            Err(e) => {
                errors.lock().unwrap().push((entry.path.clone(), e));
            }
        }
        pb.inc(1);
    });
    pb.finish_with_message("done");

    // Check for errors
    let errors = errors.into_inner().unwrap();
    if !errors.is_empty() {
        for (path, err) in &errors {
            eprintln!("  ❌ {}: {}", path, err);
        }
        bail!(
            "Decryption failed for {} file(s). Encrypted data preserved — you can retry.",
            errors.len()
        );
    }

    // ── 6. Cleanup vault data ───────────────────────────────────
    println!("🗑️  Removing encrypted data...");
    fs::remove_dir_all(&vault_data)?;
    fs::remove_file(&meta_path)?;

    println!("✅ Unlocked! {} file(s) restored.", index.files.len());
    Ok(())
}

/// Read vault metadata with automatic disaster recovery.
/// If .vault_meta is missing in the root directory, automatically restores it from .vault_data/.vault_meta.bak.
pub fn read_vault_meta(folder: &Path) -> Result<(VaultMeta, PathBuf)> {
    let meta_path = folder.join(VAULT_META_FILE);
    if meta_path.exists() {
        let content = fs::read_to_string(&meta_path)?;
        let meta: VaultMeta = serde_json::from_str(&content)?;
        Ok((meta, meta_path))
    } else {
        let backup_path = folder.join(VAULT_DATA_DIR).join(VAULT_META_BACKUP_FILE);
        if backup_path.exists() {
            println!("⚠️ 检测到主元数据文件丢失，已自动从 .vault_data 备份副本中安全恢复！");
            let content = fs::read_to_string(&backup_path)?;
            let _ = fs::write(&meta_path, &content);
            #[cfg(windows)]
            let _ = set_hidden_attribute(&meta_path);
            let meta: VaultMeta = serde_json::from_str(&content)?;
            Ok((meta, meta_path))
        } else {
            bail!("❌ 找不到元数据文件 (.vault_meta) 或其备份副本，文件夹无法解密");
        }
    }
}

/// Check if a folder is currently locked (checks primary metadata or backup).
pub fn is_locked(folder: &Path) -> bool {
    folder.join(VAULT_META_FILE).exists()
        || (folder.join(VAULT_DATA_DIR).exists()
            && folder.join(VAULT_DATA_DIR).join(VAULT_META_BACKUP_FILE).exists())
}


// ─── File Scanning ──────────────────────────────────────────────────

/// Walk the folder tree and collect all regular files and directories,
/// skipping vault internal files.
fn scan_folder(folder: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();

    for entry in WalkDir::new(folder)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != VAULT_DATA_DIR && name != VAULT_META_FILE && name != VAULT_META_BACKUP_FILE
        })
    {
        let entry = entry?;
        let ft = entry.file_type();

        if ft.is_file() {
            files.push(entry.into_path());
        } else if ft.is_dir() {
            dirs.push(entry.into_path());
        }
        // Silently skip symlinks and special files
    }

    Ok((files, dirs))
}

// ─── Index Building ─────────────────────────────────────────────────

fn build_file_entry(id: &str, path: &Path, base: &Path) -> Result<FileEntry> {
    let relative = path
        .strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let metadata = fs::metadata(path)?;
    let (modified_secs, modified_nanos) = file_mtime(&metadata);

    Ok(FileEntry {
        id: id.to_string(),
        path: relative,
        size: metadata.len(),
        modified_secs,
        modified_nanos,
        unix_mode: get_unix_mode(&metadata),
        readonly: get_readonly(&metadata),
    })
}

fn build_dir_entries(base: &Path, dirs: &[PathBuf]) -> Result<Vec<DirEntry>> {
    dirs.iter()
        .map(|dir| {
            let relative = dir
                .strip_prefix(base)
                .unwrap_or(dir)
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = fs::metadata(dir).ok();
            Ok(DirEntry {
                path: relative,
                unix_mode: metadata.as_ref().and_then(|m| get_unix_mode(m)),
            })
        })
        .collect()
}

// ─── Metadata Helpers ───────────────────────────────────────────────

fn file_mtime(metadata: &fs::Metadata) -> (i64, u32) {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unwrap_or((0, 0))
}

fn restore_file_metadata(path: &Path, entry: &FileEntry) {
    // Restore modification time
    if entry.modified_secs > 0 {
        let mtime = filetime::FileTime::from_unix_time(entry.modified_secs, entry.modified_nanos);
        let _ = filetime::set_file_mtime(path, mtime);
    }

    // Restore Unix permissions
    #[cfg(unix)]
    if let Some(mode) = entry.unix_mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }

    // Restore Windows readonly
    #[cfg(windows)]
    if let Some(readonly) = entry.readonly {
        if let Ok(md) = fs::metadata(path) {
            let mut perms = md.permissions();
            perms.set_readonly(readonly);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

#[cfg(unix)]
fn get_unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn get_unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(windows)]
fn get_readonly(metadata: &fs::Metadata) -> Option<bool> {
    Some(metadata.permissions().readonly())
}

#[cfg(not(windows))]
fn get_readonly(_metadata: &fs::Metadata) -> Option<bool> {
    None
}

// ─── Secure Deletion ────────────────────────────────────────────────

/// Overwrite a file with zeros before unlinking. This mitigates casual
/// recovery from HDD; on SSD the OS/firmware may still retain data due
/// to wear-leveling, but this is the best user-space mitigation.
fn secure_delete(path: &Path) -> Result<()> {
    // Make file writable first (needed on Windows for readonly files)
    if let Ok(md) = fs::metadata(path) {
        if md.permissions().readonly() {
            let mut perms = md.permissions();
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }

    let len = fs::metadata(path)?.len();

    if len > 0 {
        use std::io::Write;
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; 8192];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(8192) as usize;
            file.write_all(&zeros[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}

/// Remove empty directories under `folder`, deepest first.
fn remove_empty_dirs(folder: &Path) -> Result<()> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    for entry in WalkDir::new(folder)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != VAULT_DATA_DIR && name != VAULT_META_FILE
        })
    {
        if let Ok(entry) = entry {
            if entry.file_type().is_dir() {
                dirs.push(entry.into_path());
            }
        }
    }

    // Sort deepest first
    dirs.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
    });

    for dir in dirs {
        // Only remove if truly empty
        if dir.read_dir().map(|mut d| d.next().is_none()).unwrap_or(false) {
            let _ = fs::remove_dir(&dir);
        }
    }

    Ok(())
}

// ─── Platform Helpers ───────────────────────────────────────────────

/// Set the hidden attribute on a file or directory (Windows only).
#[cfg(windows)]
fn set_hidden_attribute(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("attrib")
        .arg("+H")
        .arg(path.as_os_str())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()?;
    Ok(())
}

/// Canonicalize a path without the Windows `\\?\` prefix.
fn dunce_canonicalize(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;

    // Strip the \\?\ prefix on Windows for cleaner display
    #[cfg(windows)]
    {
        let s = canonical.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(stripped));
        }
    }

    Ok(canonical)
}

// ─── UI Helpers ─────────────────────────────────────────────────────

fn make_progress_bar(total: u64, action: &str, color: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    let template = format!(
        "  {} [{{bar:40.{}/blue}}] {{pos}}/{{len}} {{msg}}",
        action, color
    );
    pb.set_style(
        ProgressStyle::with_template(&template)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
    );
    pb
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("securevault_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn create_test_file(dir: &Path, relative: &str, content: &[u8]) {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
    }

    #[test]
    fn test_lock_unlock_roundtrip() {
        let dir = setup_test_folder("roundtrip");

        // Create test files
        create_test_file(&dir, "hello.txt", b"Hello, World!");
        create_test_file(&dir, "sub/nested.txt", b"Nested file content");
        create_test_file(&dir, "sub/deep/file.bin", &[0xDE, 0xAD, 0xBE, 0xEF]);
        create_test_file(&dir, "empty.txt", b"");

        let password = "test-password-12345";

        // Lock
        lock(&dir, password).unwrap();
        assert!(is_locked(&dir));

        // Verify originals are gone
        assert!(!dir.join("hello.txt").exists());
        assert!(!dir.join("sub/nested.txt").exists());

        // Verify vault data exists
        assert!(dir.join(VAULT_META_FILE).exists());
        assert!(dir.join(VAULT_DATA_DIR).exists());

        // Unlock
        unlock(&dir, password).unwrap();
        assert!(!is_locked(&dir));

        // Verify files are restored
        assert_eq!(fs::read_to_string(dir.join("hello.txt")).unwrap(), "Hello, World!");
        assert_eq!(
            fs::read_to_string(dir.join("sub/nested.txt")).unwrap(),
            "Nested file content"
        );
        assert_eq!(
            fs::read(dir.join("sub/deep/file.bin")).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(fs::read(dir.join("empty.txt")).unwrap().len(), 0);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wrong_password_rejected() {
        let dir = setup_test_folder("wrong_pw");
        create_test_file(&dir, "secret.txt", b"Top secret data");

        lock(&dir, "correct-password").unwrap();

        let result = unlock(&dir, "wrong-password!!");
        assert!(result.is_err());
        assert!(is_locked(&dir)); // Should still be locked

        // Cleanup: unlock with correct password first
        unlock(&dir, "correct-password").unwrap();
        let _ = fs::remove_dir_all(&dir);
    }


    #[test]
    fn test_already_locked_error() {
        let dir = setup_test_folder("already_locked");
        create_test_file(&dir, "test.txt", b"test");

        lock(&dir, "password1234").unwrap();

        // Locking again should fail
        let result = lock(&dir, "password1234");
        assert!(result.is_err());

        unlock(&dir, "password1234").unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_delete_meta_recovery() {
        let dir = setup_test_folder("delete_meta_recovery");
        create_test_file(&dir, "secret.txt", b"Resilient against accidental metadata deletion");

        lock(&dir, "my-pass-789").unwrap();
        assert!(dir.join(VAULT_META_FILE).exists());
        assert!(dir.join(VAULT_DATA_DIR).join(VAULT_META_BACKUP_FILE).exists());

        // Simulate user accidentally deleting .vault_meta
        fs::remove_file(dir.join(VAULT_META_FILE)).unwrap();
        assert!(!dir.join(VAULT_META_FILE).exists());

        // is_locked should still detect it thanks to the backup
        assert!(is_locked(&dir));

        // Unlock should seamlessly auto-recover from backup and decrypt successfully!
        unlock(&dir, "my-pass-789").unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("secret.txt")).unwrap(),
            "Resilient against accidental metadata deletion"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(512), "512 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
        assert_eq!(format_size(1073741824), "1.00 GB");
    }
}
