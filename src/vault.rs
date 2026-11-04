use crate::crypto::{CryptoEngine, FileDigest, DEFAULT_CHUNK_SIZE};
use crate::index::*;
use anyhow::{bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use uuid::Uuid;
use walkdir::WalkDir;

mod incremental;
mod incremental_storage;
mod incremental_source;
#[allow(unused_imports)]
pub use incremental::{append, AppendReport};

// ─── Concurrency Budget Helpers ─────────────────────────────────────

fn get_crypto_thread_pool() -> Result<rayon::ThreadPool> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let max_threads = cores.clamp(2, 8);
    rayon::ThreadPoolBuilder::new()
        .num_threads(max_threads)
        .thread_name(|i| format!("sv-worker-{}", i))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build crypto thread pool: {}", e))
}

fn get_cleanup_thread_pool() -> Result<rayon::ThreadPool> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let max_threads = cores.clamp(2, 4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(max_threads)
        .thread_name(|i| format!("sv-cleanup-{}", i))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build cleanup thread pool: {}", e))
}

// ─── Public API ─────────────────────────────────────────────────────

/// Result of a lock (encryption) operation that may have skipped locked/in-use files.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LockReport {
    /// Files successfully encrypted.
    pub encrypted_files: usize,
    /// Total bytes of files encrypted.
    pub total_encrypted_bytes: u64,
    /// Files that could not be opened for writing and were skipped (path, reason).
    pub skipped_files: Vec<(PathBuf, String)>,
}

impl LockReport {
    /// Returns true if all files were encrypted and none were skipped.
    pub fn is_complete(&self) -> bool {
        self.skipped_files.is_empty()
    }
}

/// Check if a file can be opened for writing and securely deleted.
/// If the file is marked read-only (common in git repositories or copied media),
/// attempts to clear the read-only attribute first.
fn check_file_writable(path: &Path) -> Result<(), std::io::Error> {
    if let Ok(md) = fs::metadata(path) {
        if md.permissions().readonly() {
            let mut perms = md.permissions();
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Test opening with GENERIC_READ | GENERIC_WRITE, sharing FILE_SHARE_READ.
        // This ensures no other process has exclusive write locks.
        let _ = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0x0000_0001)
            .open(path)?;
    }
    #[cfg(not(windows))]
    {
        let _ = fs::OpenOptions::new().write(true).open(path)?;
    }
    Ok(())
}

/// Encrypt and lock a folder in-place.
///
/// 1. Scans all files and directories
/// 2. Pre-checks write access on files, skipping in-use/locked files without aborting others
/// 3. Encrypts each file → .vault_data/{uuid}.enc with lock-free collection
/// 4. Writes encrypted index → .vault_meta
/// 5. Safely overwrites and deletes original files with bounded concurrency
/// 6. Reuses scanned directory structure to eliminate duplicate filesystem walks
pub fn lock(folder: &Path, password: &str) -> Result<LockReport> {
    lock_with_progress(folder, password, |_, _, _, _| {})
}

/// Encrypt and lock a folder in-place with real-time per-file progress callback.
///
/// Progress callback receives: `(completed_files, total_files, current_relative_path, file_size)`
pub fn lock_with_progress<F>(folder: &Path, password: &str, progress: F) -> Result<LockReport>
where
    F: Fn(usize, usize, &str, u64) + Send + Sync,
{
    let folder = dunce_canonicalize(folder)?;
    let _operation = incremental::operation_lock(&folder)?;

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
        return Ok(LockReport {
            encrypted_files: 0,
            total_encrypted_bytes: 0,
            skipped_files: Vec::new(),
        });
    }
    println!(
        "📊 Found {} file(s) in {} director(ies)",
        files.len(),
        dirs.len() + 1
    );

    // Pre-check: Determine which files can be opened for writing and which are locked/in-use
    let mut files_to_encrypt = Vec::with_capacity(files.len());
    let mut skipped_files = Vec::new();

    for file_path in files {
        match check_file_writable(&file_path) {
            Ok(()) => files_to_encrypt.push(file_path),
            Err(e) => {
                let err_msg = format!("{}", e);
                eprintln!(
                    "  ⚠️ File '{}' cannot be opened for writing (skipped): {}",
                    file_path.display(),
                    err_msg
                );
                skipped_files.push((file_path, err_msg));
            }
        }
    }

    if files_to_encrypt.is_empty() {
        bail!(
            "Cannot lock folder: all files ({} file(s)) cannot be opened for writing (possibly in use by another program). Aborted without modifying any files.",
            skipped_files.len()
        );
    }

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

    // ── 4. Encrypt files in parallel (Lock-free collection & bounded pool) ───
    let pb = make_progress_bar(files_to_encrypt.len() as u64, "Encrypting", "cyan");
    let crypto_pool = get_crypto_thread_pool()?;
    let total_files = files_to_encrypt.len();
    let counter = std::sync::atomic::AtomicUsize::new(0);

    let results: Vec<Result<FileEntry, (PathBuf, anyhow::Error)>> = crypto_pool.install(|| {
        files_to_encrypt
            .par_iter()
            .map(|file_path| {
                let id = Uuid::new_v4().to_string();
                let enc_path = vault_data.join(format!("{}.enc", id));

                let res = match crypto.encrypt_file(file_path, &enc_path) {
                    Ok(digest) => {
                        match build_file_entry(&id, file_path, &folder, Some(digest)) {
                            Ok(entry) => {
                                let completed = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                pb.inc(1);
                                let rel = file_path.strip_prefix(&folder).unwrap_or(file_path).to_string_lossy();
                                progress(completed, total_files, &rel, entry.size);
                                Ok(entry)
                            }
                            Err(e) => {
                                pb.inc(1);
                                Err((file_path.clone(), e))
                            }
                        }
                    }
                    Err(e) => {
                        pb.inc(1);
                        Err((file_path.clone(), e))
                    }
                };
                res
            })
            .collect()
    });
    pb.finish_with_message("done");

    // Partition results without lock contention
    let mut file_entries = Vec::with_capacity(results.len());
    let mut errors = Vec::new();
    for res in results {
        match res {
            Ok(entry) => file_entries.push(entry),
            Err(err) => errors.push(err),
        }
    }

    // Check for encryption errors — abort if any
    if !errors.is_empty() {
        let _ = fs::remove_dir_all(&vault_data);
        for (path, err) in &errors {
            eprintln!("  ❌ {}: {}", path.display(), err);
        }
        bail!("Encryption failed for {} file(s) — aborted", errors.len());
    }

    // ── 5. Build and encrypt index ──────────────────────────────
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

    // ── 7. Delete originals with bounded concurrency & error collection ───────
    let pb = make_progress_bar(files_to_encrypt.len() as u64, "Cleaning up", "red");
    let cleanup_pool = get_cleanup_thread_pool()?;

    let cleanup_results: Vec<Result<(), (PathBuf, anyhow::Error)>> = cleanup_pool.install(|| {
        files_to_encrypt
            .par_iter()
            .map(|file_path| {
                let res = secure_delete(file_path).map_err(|e| (file_path.clone(), e));
                pb.inc(1);
                res
            })
            .collect()
    });
    pb.finish_with_message("done");

    let cleanup_errors: Vec<_> = cleanup_results
        .into_iter()
        .filter_map(|r| r.err())
        .collect();

    // Remove emptied directories (deepest first), reusing scanned `dirs` without re-walking filesystem!
    let mut sorted_dirs = dirs.clone();
    sorted_dirs.sort_by(|a, b| b.components().count().cmp(&a.components().count()));
    for dir in &sorted_dirs {
        let _ = fs::remove_dir(dir);
    }

    // Hide vault files on Windows
    #[cfg(windows)]
    {
        let _ = set_hidden_attribute(&vault_data);
        let _ = set_hidden_attribute(&folder.join(VAULT_META_FILE));
    }

    // If any cleanup failed, DO NOT falsely claim success!
    if !cleanup_errors.is_empty() {
        for (path, err) in &cleanup_errors {
            eprintln!("  ❌ Could not securely delete {}: {}", path.display(), err);
        }
        bail!(
            "Vault encrypted, but {} original file(s) could not be securely deleted (file in use or permission denied). Originals remain on disk: {:?}",
            cleanup_errors.len(),
            cleanup_errors.iter().map(|(p, _)| p.display().to_string()).collect::<Vec<_>>()
        );
    }

    let total_size: u64 = index.files.iter().map(|f| f.size).sum();
    if skipped_files.is_empty() {
        println!(
            "✅ Locked! {} file(s), {} encrypted.",
            index.files.len(),
            format_size(total_size)
        );
    } else {
        println!(
            "⚠️ Partially locked! {} file(s) ({}) encrypted, {} file(s) skipped.",
            index.files.len(),
            format_size(total_size),
            skipped_files.len()
        );
    }
    Ok(LockReport {
        encrypted_files: index.files.len(),
        total_encrypted_bytes: total_size,
        skipped_files,
    })
}

/// Result of an unlock operation that may have partial successes.
#[derive(Debug)]
#[allow(dead_code)]
pub struct UnlockReport {
    /// Files that were successfully decrypted and restored.
    pub restored: Vec<String>,
    /// Files that failed to decrypt (path, error message).
    pub failed: Vec<(String, String)>,
    /// Whether the vault data was fully cleaned up (true only when all files succeeded).
    pub vault_cleaned: bool,
}

impl UnlockReport {
    /// Returns true if all files were successfully restored.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Decrypt and unlock a locked folder.
///
/// Fault-tolerant: if some encrypted files are missing or corrupted,
/// the remaining files are still decrypted successfully. Returns `Ok` with
/// an `UnlockReport` describing which files succeeded and which failed.
/// Only returns `Err` for fatal errors (wrong password, corrupted index, etc.).
pub fn unlock(folder: &Path, password: &str) -> Result<UnlockReport> {
    unlock_with_progress(folder, password, |_, _, _, _| {})
}

/// Decrypt and unlock a locked folder in-place with real-time per-file progress callback.
///
/// Fault-tolerant: successfully decrypts available files even if some are missing or corrupted.
/// Progress callback receives: `(completed_files, total_files, current_relative_path, file_size)`
pub fn unlock_with_progress<F>(folder: &Path, password: &str, progress: F) -> Result<UnlockReport>
where
    F: Fn(usize, usize, &str, u64) + Send + Sync,
{
    let folder = dunce_canonicalize(folder)?;
    let _operation = incremental::operation_lock(&folder)?;

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

    incremental::check_restore_targets(&folder, &index)?;

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
        if !dir_path.exists() {
            fs::create_dir_all(&dir_path)?;
        }

        #[cfg(unix)]
        if let Some(mode) = dir.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir_path, fs::Permissions::from_mode(mode));
        }
    }

    // ── 5. Decrypt files in parallel (fault-tolerant) ───────────
    let vault_data = folder.join(VAULT_DATA_DIR);
    let pb = make_progress_bar(index.files.len() as u64, "Decrypting", "green");
    let crypto_pool = get_crypto_thread_pool()?;
    let total_files = index.files.len();
    let counter = std::sync::atomic::AtomicUsize::new(0);

    // Each result carries: Ok((restored_path, entry_id)) or Err((rel_path, error))
    let results: Vec<Result<(PathBuf, String), (String, anyhow::Error)>> = crypto_pool.install(|| {
        index
            .files
            .par_iter()
            .map(|entry| {
                let enc_path = vault_data.join(format!("{}.enc", entry.id));
                let dst_path = folder.join(&entry.path);

                // Only create parent directory if not already existing
                if let Some(parent) = dst_path.parent() {
                    if !parent.exists() {
                        let _ = fs::create_dir_all(parent);
                    }
                }

                // Authenticated decryption with expected size & SHA-256
                match crypto.decrypt_file_authenticated(
                    &enc_path,
                    &dst_path,
                    Some(entry.size),
                    entry.sha256.as_deref(),
                ) {
                    Ok(_) => {
                        restore_file_metadata(&dst_path, entry);
                        let completed = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        pb.inc(1);
                        progress(completed, total_files, &entry.path, entry.size);
                        Ok((dst_path, entry.id.clone()))
                    }
                    Err(e) => {
                        // Clean up any partially written destination file
                        let _ = fs::remove_file(&dst_path);
                        let completed = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        pb.inc(1);
                        progress(completed, total_files, &entry.path, 0);
                        Err((entry.path.clone(), e))
                    }
                }
            })
            .collect()
    });
    pb.finish_with_message("done");

    let mut restored_paths: Vec<String> = Vec::new();
    let mut restored_enc_ids: Vec<String> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();
    for r in results {
        match r {
            Ok((path, enc_id)) => {
                restored_paths.push(path.strip_prefix(&folder).unwrap_or(&path).to_string_lossy().into_owned());
                restored_enc_ids.push(enc_id);
            }
            Err((path, err)) => {
                eprintln!("  ⚠️  Failed to decrypt: {} — {}", path, err);
                errors.push((path, err.to_string()));
            }
        }
    }

    // ── 6. Cleanup ──────────────────────────────────────────────
    let vault_cleaned = if errors.is_empty() {
        // All files restored successfully — clean up entire vault
        println!("🗑️  Removing encrypted data...");
        fs::remove_dir_all(&vault_data)?;
        fs::remove_file(&meta_path)?;
        println!("✅ Unlocked! {} file(s) restored.", restored_paths.len());
        true
    } else {
        // Partial success — remove only the .enc files for successfully restored files,
        // keep vault metadata and remaining .enc files so the user can retry.
        println!(
            "⚠️  Partial unlock: {} file(s) restored, {} file(s) failed.",
            restored_paths.len(),
            errors.len()
        );
        for enc_id in &restored_enc_ids {
            let enc_file = vault_data.join(format!("{}.enc", enc_id));
            let _ = fs::remove_file(&enc_file);
        }

        // Update the index to only contain the failed (remaining) entries
        let remaining_ids: std::collections::HashSet<&str> = restored_enc_ids.iter().map(|s| s.as_str()).collect();
        let remaining_files: Vec<FileEntry> = index.files.into_iter()
            .filter(|e| !remaining_ids.contains(e.id.as_str()))
            .collect();

        if remaining_files.is_empty() {
            // Edge case: all files actually restored but with non-fatal errors logged
            fs::remove_dir_all(&vault_data)?;
            fs::remove_file(&meta_path)?;
        } else {
            // Rewrite the vault index with only the remaining (failed) entries
            let updated_index = VaultIndex {
                version: index.version,
                files: remaining_files,
                dirs: index.dirs,
            };
            let updated_json = serde_json::to_vec(&updated_index)?;
            let updated_encrypted = crypto.encrypt_index(&updated_json)?;

            let updated_meta = VaultMeta {
                version: meta.version,
                salt: meta.salt.clone(),
                password_check: meta.password_check.clone(),
                chunk_size: meta.chunk_size,
                encrypted_index: BASE64.encode(&updated_encrypted),
            };
            let updated_meta_json = serde_json::to_string_pretty(&updated_meta)?;
            fs::write(&meta_path, &updated_meta_json)?;
            let _ = fs::write(vault_data.join(VAULT_META_BACKUP_FILE), &updated_meta_json);
        }

        for (path, err) in &errors {
            eprintln!("  ❌ {}: {}", path, err);
        }
        println!("💡 Encrypted vault preserved for failed files — you can retry after fixing the issue.");
        false
    };

    Ok(UnlockReport {
        restored: restored_paths,
        failed: errors,
        vault_cleaned,
    })
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
                && name != incremental::OPERATION_LOCK
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

fn build_file_entry(id: &str, path: &Path, base: &Path, digest: Option<FileDigest>) -> Result<FileEntry> {
    let relative = path
        .strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let metadata = fs::metadata(path)?;
    let (modified_secs, modified_nanos) = file_mtime(&metadata);
    let (size, sha256) = match digest {
        Some(d) => (d.size, Some(d.sha256_hex())),
        None => (metadata.len(), None),
    };

    Ok(FileEntry {
        id: id.to_string(),
        path: relative,
        size,
        modified_secs,
        modified_nanos,
        unix_mode: get_unix_mode(&metadata),
        readonly: get_readonly(&metadata),
        sha256,
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

const SECURE_DELETE_BUF_SIZE: usize = 256 * 1024; // 256 KiB
static ZERO_BUF: [u8; SECURE_DELETE_BUF_SIZE] = [0u8; SECURE_DELETE_BUF_SIZE];

/// Overwrite a file with zeros before unlinking using a reusable 256 KiB buffer.
/// This mitigates casual recovery from HDD; on SSD the OS/firmware may still retain data due
/// to wear-leveling, but this is the best user-space mitigation.
/// Includes fsync (sync_all) to ensure data is physically written to disk.
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
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(SECURE_DELETE_BUF_SIZE as u64) as usize;
            file.write_all(&ZERO_BUF[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;
    }

    fs::remove_file(path)?;
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
    fn test_progress_callbacks() {
        let dir = setup_test_folder("progress_cb");
        create_test_file(&dir, "f1.txt", b"Content 1");
        create_test_file(&dir, "f2.txt", b"Content 2");
        create_test_file(&dir, "f3.txt", b"Content 3");

        let password = "pass-test-progress";
        let lock_count = std::sync::atomic::AtomicUsize::new(0);
        lock_with_progress(&dir, password, |_completed, total, path, size| {
            assert_eq!(total, 3);
            assert!(size > 0);
            assert!(!path.is_empty());
            lock_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }).unwrap();
        assert_eq!(lock_count.load(std::sync::atomic::Ordering::SeqCst), 3);

        let unlock_count = std::sync::atomic::AtomicUsize::new(0);
        unlock_with_progress(&dir, password, |_completed, total, path, size| {
            assert_eq!(total, 3);
            assert!(size > 0);
            assert!(!path.is_empty());
            unlock_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }).unwrap();
        assert_eq!(unlock_count.load(std::sync::atomic::Ordering::SeqCst), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_projects_batch_roundtrip() {
        let p1 = setup_test_folder("proj_1");
        let p2 = setup_test_folder("proj_2");
        let p3 = setup_test_folder("proj_3");

        create_test_file(&p1, "doc1.txt", b"Proj 1 Content");
        create_test_file(&p1, "sub/a.bin", &[1, 2, 3]);

        create_test_file(&p2, "doc2.txt", b"Proj 2 Content");

        create_test_file(&p3, "doc3.txt", b"Proj 3 Content");
        create_test_file(&p3, "sub/b.bin", &[4, 5, 6]);
        create_test_file(&p3, "sub/c.bin", &[7, 8, 9]);

        let projects = [&p1, &p2, &p3];
        let password = "batch-test-password-999";

        // Batch lock all 3 projects
        let total_encrypted_files = std::sync::atomic::AtomicUsize::new(0);
        for proj in &projects {
            assert!(!is_locked(proj));
            lock_with_progress(proj, password, |_comp, _tot, _f, _sz| {
                total_encrypted_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }).unwrap();
            assert!(is_locked(proj));
        }
        assert_eq!(total_encrypted_files.load(std::sync::atomic::Ordering::SeqCst), 6);

        // Batch unlock all 3 projects
        let total_decrypted_files = std::sync::atomic::AtomicUsize::new(0);
        for proj in &projects {
            assert!(is_locked(proj));
            unlock_with_progress(proj, password, |_comp, _tot, _f, _sz| {
                total_decrypted_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }).unwrap();
            assert!(!is_locked(proj));
        }
        assert_eq!(total_decrypted_files.load(std::sync::atomic::Ordering::SeqCst), 6);

        // Verify all contents
        assert_eq!(fs::read_to_string(p1.join("doc1.txt")).unwrap(), "Proj 1 Content");
        assert_eq!(fs::read(p1.join("sub/a.bin")).unwrap(), vec![1, 2, 3]);
        assert_eq!(fs::read_to_string(p2.join("doc2.txt")).unwrap(), "Proj 2 Content");
        assert_eq!(fs::read_to_string(p3.join("doc3.txt")).unwrap(), "Proj 3 Content");
        assert_eq!(fs::read(p3.join("sub/b.bin")).unwrap(), vec![4, 5, 6]);
        assert_eq!(fs::read(p3.join("sub/c.bin")).unwrap(), vec![7, 8, 9]);

        let _ = fs::remove_dir_all(&p1);
        let _ = fs::remove_dir_all(&p2);
        let _ = fs::remove_dir_all(&p3);
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

    #[test]
    fn test_unlock_partial_success_with_corrupted_file() {
        let dir = setup_test_folder("partial_success");
        create_test_file(&dir, "good1.txt", b"Good file 1");
        create_test_file(&dir, "good2.txt", b"Good file 2");
        create_test_file(&dir, "corrupt.txt", b"Corrupted content target");

        let password = "my-secure-password-123";
        lock(&dir, password).unwrap();

        // Corrupt one encrypted blob in .vault_data
        let vault_data = dir.join(VAULT_DATA_DIR);
        let mut enc_files: Vec<_> = fs::read_dir(&vault_data)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|ext| ext.to_str()) == Some("enc"))
            .collect();
        assert!(!enc_files.is_empty());
        let target_file = enc_files.pop().unwrap();
        // Tamper with the encrypted file
        let mut bytes = fs::read(&target_file).unwrap();
        let idx = bytes.len() - 1;
        bytes[idx] ^= 0xFF;
        fs::write(&target_file, &bytes).unwrap();

        // Unlock should succeed (fault-tolerant) but report partial failure
        let report = unlock(&dir, password).unwrap();
        assert!(!report.is_complete(), "Should have partial failures");
        assert_eq!(report.failed.len(), 1, "Exactly one file should fail");
        assert_eq!(report.restored.len(), 2, "Two files should be restored successfully");
        assert!(!report.vault_cleaned, "Vault data should be preserved for failed files");

        // The corrupted file's plaintext should NOT exist (cleaned up)
        // The two good files should be restored
        let mut restored_count = 0;
        if dir.join("good1.txt").exists() { restored_count += 1; }
        if dir.join("good2.txt").exists() { restored_count += 1; }
        if dir.join("corrupt.txt").exists() { restored_count += 1; }
        // At least 2 files should be restored (the good ones); the corrupted one may or may not
        // depending on which file was tampered (we tampered the last in the list)
        assert!(restored_count >= 2, "At least 2 good files should be restored, got {}", restored_count);

        // Vault metadata should still exist (for retry)
        assert!(dir.join(VAULT_META_FILE).exists(), "Vault meta should be preserved");
        assert!(dir.join(VAULT_DATA_DIR).exists(), "Vault data dir should be preserved");

        // The remaining .enc files should only be for the failed file(s)
        let remaining_enc: Vec<_> = fs::read_dir(&vault_data)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|ext| ext.to_str()) == Some("enc"))
            .collect();
        assert_eq!(remaining_enc.len(), 1, "Only the failed file's .enc should remain");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_unlock_with_deleted_enc_file() {
        let dir = setup_test_folder("deleted_enc");
        create_test_file(&dir, "file_a.txt", b"Content A");
        create_test_file(&dir, "file_b.txt", b"Content B");
        create_test_file(&dir, "file_c.txt", b"Content C");

        let password = "delete-test-pw-456";
        lock(&dir, password).unwrap();

        // Delete one .enc file entirely
        let vault_data = dir.join(VAULT_DATA_DIR);
        let enc_files: Vec<_> = fs::read_dir(&vault_data)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|ext| ext.to_str()) == Some("enc"))
            .collect();
        assert_eq!(enc_files.len(), 3);
        fs::remove_file(&enc_files[0]).unwrap(); // Delete one

        // Unlock should succeed with partial results
        let report = unlock(&dir, password).unwrap();
        assert!(!report.is_complete());
        assert_eq!(report.restored.len(), 2, "Two files should be restored");
        assert_eq!(report.failed.len(), 1, "One file should fail (missing .enc)");

        // Vault preserved for the missing file
        assert!(dir.join(VAULT_META_FILE).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_lock_readonly_git_files() {
        let dir = setup_test_folder("readonly_git");
        create_test_file(&dir, "git_obj.bin", b"git object 12345");
        let path = dir.join("git_obj.bin");
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&path, perms).unwrap();

        let password = "pass-test-readonly";
        let report = lock(&dir, password).unwrap();
        assert!(report.is_complete());
        assert_eq!(report.encrypted_files, 1);
        assert!(!path.exists());

        let un_report = unlock(&dir, password).unwrap();
        assert!(un_report.is_complete());
        assert_eq!(fs::read(&path).unwrap(), b"git object 12345");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_lock_tolerant_with_locked_file() {
        let dir = setup_test_folder("tolerant_lock");
        create_test_file(&dir, "free.txt", b"I can be encrypted");
        create_test_file(&dir, "locked.txt", b"I am currently in use");

        let locked_path = dir.join("locked.txt");
        let free_path = dir.join("free.txt");

        #[cfg(windows)]
        let lock_guard = {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ: allows reading, but denies all writers (causing check_file_writable to fail)
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0x0000_0001)
                .open(&locked_path)
                .unwrap()
        };

        let password = "pass-test-tolerant";

        #[cfg(windows)]
        {
            let report = lock(&dir, password).unwrap();
            assert!(!report.is_complete());
            assert_eq!(report.encrypted_files, 1);
            assert_eq!(report.skipped_files.len(), 1);

            // free.txt was encrypted and deleted
            assert!(!free_path.exists());
            // locked.txt was skipped and remains plaintext
            assert!(locked_path.exists());
            assert_eq!(fs::read(&locked_path).unwrap(), b"I am currently in use");
            assert!(is_locked(&dir));

            // Release lock
            drop(lock_guard);

            // Now run append to continue encrypting the previously skipped file
            let append_report = append(&dir, password).unwrap();
            assert!(append_report.is_complete());
            assert_eq!(append_report.added, 1);
            assert!(!locked_path.exists());

            // Unlock and verify both files
            let unlock_report = unlock(&dir, password).unwrap();
            assert!(unlock_report.is_complete());
            assert_eq!(fs::read(&free_path).unwrap(), b"I can be encrypted");
            assert_eq!(fs::read(&locked_path).unwrap(), b"I am currently in use");
        }

        #[cfg(not(windows))]
        {
            let report = lock(&dir, password).unwrap();
            assert!(report.is_complete());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_append_tolerant_with_locked_file() {
        let dir = setup_test_folder("tolerant_append");
        create_test_file(&dir, "initial.txt", b"Initial secure content");

        let password = "pass-test-append-tolerant";
        lock(&dir, password).unwrap();
        assert!(is_locked(&dir));

        create_test_file(&dir, "new_free.txt", b"New free content");
        create_test_file(&dir, "new_locked.txt", b"New locked content");

        let new_locked_path = dir.join("new_locked.txt");
        let new_free_path = dir.join("new_free.txt");

        #[cfg(windows)]
        let lock_guard = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0x0000_0001)
                .open(&new_locked_path)
                .unwrap()
        };

        #[cfg(windows)]
        {
            let report = append(&dir, password).unwrap();
            assert!(!report.is_complete());
            assert_eq!(report.added, 1);
            assert_eq!(report.skipped.len(), 1);

            // new_free.txt was encrypted
            assert!(!new_free_path.exists());
            // new_locked.txt remains plaintext
            assert!(new_locked_path.exists());
            assert_eq!(fs::read(&new_locked_path).unwrap(), b"New locked content");

            // Release lock and append again
            drop(lock_guard);
            let append_report = append(&dir, password).unwrap();
            assert!(append_report.is_complete());
            assert_eq!(append_report.added, 1);
            assert!(!new_locked_path.exists());

            // Unlock and verify all 3 files
            let unlock_report = unlock(&dir, password).unwrap();
            assert!(unlock_report.is_complete());
            assert_eq!(fs::read(dir.join("initial.txt")).unwrap(), b"Initial secure content");
            assert_eq!(fs::read(&new_free_path).unwrap(), b"New free content");
            assert_eq!(fs::read(&new_locked_path).unwrap(), b"New locked content");
        }

        #[cfg(not(windows))]
        {
            let report = append(&dir, password).unwrap();
            assert!(report.is_complete());
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
