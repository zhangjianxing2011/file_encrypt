use super::incremental_storage::{replace_synced, sync_dir};
use super::*;
use anyhow::Context;
use std::collections::BTreeMap;
use std::io::Write;

pub(super) const OPERATION_LOCK: &str = ".vault_operation.lock";

// Keep this empty file in place: unlinking it allows two processes to lock
// different inodes. The operating system releases the lock on process exit.
pub(super) fn operation_lock(folder: &Path) -> Result<fs::File> {
    let path = folder.join(OPERATION_LOCK);
    if let Ok(md) = fs::symlink_metadata(&path) {
        ensure!(
            md.is_file() && !is_link(&md),
            "Invalid vault operation lock"
        );
        ensure!(md.len() == 0, "Reserved operation lock contains user data");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.try_lock()
        .map_err(|e| anyhow::anyhow!("文件夹正在执行其他加解密操作，或无法取得操作锁: {e}"))?;
    Ok(file)
}

fn is_link(md: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        md.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        md.file_type().is_symlink()
    }
}

fn regular(path: &Path, directory: bool) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        !is_link(&md) && if directory { md.is_dir() } else { md.is_file() },
        "Unsupported link or special file: {}",
        path.display()
    );
    Ok(())
}

fn path_key(path: &str) -> Result<String> {
    ensure!(
        !path.is_empty() && !path.contains('\\'),
        "Invalid vault path: {path}"
    );
    for part in path.split('/') {
        let lower = part.to_lowercase();
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with([' ', '.'])
                && !part
                    .chars()
                    .any(|c| c.is_control() || ":*?\"<>|".contains(c)),
            "Invalid vault path: {path}"
        );
        ensure!(
            ![
                VAULT_DATA_DIR,
                VAULT_META_FILE,
                VAULT_META_BACKUP_FILE,
                OPERATION_LOCK
            ]
            .contains(&lower.as_str()),
            "Reserved vault path: {path}"
        );
        let stem = lower.split('.').next().unwrap_or("");
        ensure!(
            !["con", "prn", "aux", "nul"].contains(&stem)
                && !(stem.len() == 4
                    && (stem.starts_with("com") || stem.starts_with("lpt"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "Reserved device path: {path}"
        );
    }
    Ok(path.to_lowercase())
}

// Include implicit parent directories, so conflicts work with older indexes
// that omitted a parent directory entry as well.
fn register(paths: &mut BTreeMap<String, (String, bool)>, path: &str, dir: bool) -> Result<bool> {
    let key = path_key(path)?;
    if let Some((spelling, was_dir)) = paths.get(&key) {
        ensure!(dir && *was_dir && spelling == path, "Path conflict: {path}");
        return Ok(false);
    }
    if let Some((parent, _)) = path.rsplit_once('/') {
        register(paths, parent, true)?;
    }
    paths.insert(key, (path.to_owned(), dir));
    Ok(true)
}

/// Refuse to overwrite plaintext left by an append/cleanup failure. Validate
/// the complete restore plan before creating any output or changing permissions.
pub(super) fn check_restore_targets(folder: &Path, index: &VaultIndex) -> Result<()> {
    // Existing vaults can contain platform-specific names (e.g. ':' or distinct
    // 'a'/'A' on Unix). Do not apply append's portable-name restrictions here.
    for (relative, directory) in index
        .dirs
        .iter()
        .map(|d| (&d.path, true))
        .chain(index.files.iter().map(|f| (&f.path, false)))
    {
        let relative_path = Path::new(relative);
        ensure!(
            !relative.is_empty()
                && relative
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != "..")
                && relative_path
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "Invalid restore path: {relative}"
        );
        #[cfg(windows)]
        ensure!(
            !relative.contains(':') && !relative.contains('\\'),
            "Invalid restore path: {relative}"
        );
        let mut target = folder.to_path_buf();
        let parts: Vec<_> = relative_path.components().collect();
        for (i, part) in parts.iter().enumerate() {
            target.push(part.as_os_str());
            let needs_directory = directory || i + 1 < parts.len();
            match fs::symlink_metadata(&target) {
                Ok(md) => ensure!(
                    needs_directory && md.is_dir() && !is_link(&md),
                    "解密路径冲突，请先将现存明文或冲突项移到安全位置: {}",
                    target.display()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    AfterBlob,
    BeforePrimary,
    AfterPrimary,
    BeforeCleanup,
}

#[derive(Default)]
struct Pending {
    blobs: Vec<PathBuf>,
    temporary: Vec<PathBuf>,
    committed: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        for p in &self.temporary {
            let _ = fs::remove_file(p);
        }
        if !self.committed {
            for p in &self.blobs {
                let _ = fs::remove_file(p);
            }
        }
    }
}

fn stage_meta(data: &Path, bytes: &[u8], pending: &mut Pending) -> Result<PathBuf> {
    let path = data.join(format!("{}.meta.tmp", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    pending.temporary.push(path.clone());
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(path)
}

/// Encrypt newly added plaintext without rewriting existing encrypted blobs.
pub fn append(folder: &Path, password: &str) -> Result<usize> {
    append_with_hook(folder, password, |_| Ok(()))
}

fn append_with_hook(
    folder: &Path,
    password: &str,
    mut hook: impl FnMut(Stage) -> Result<()>,
) -> Result<usize> {
    let folder = dunce_canonicalize(folder)?;
    let _operation = operation_lock(&folder)?;
    ensure!(is_locked(&folder), "Folder is not locked; encrypt it first");
    let data = folder.join(VAULT_DATA_DIR);
    regular(&data, true)?;
    let primary = folder.join(VAULT_META_FILE);
    let backup = data.join(VAULT_META_BACKUP_FILE);
    let metadata_path = if primary.exists() { &primary } else { &backup };
    regular(metadata_path, false)?;
    let mut meta: VaultMeta = serde_json::from_slice(&fs::read(metadata_path)?)?;
    ensure!(
        meta.version == 1 && meta.chunk_size > 0 && meta.chunk_size <= 64 * 1024 * 1024,
        "Unsupported vault metadata"
    );
    let crypto = CryptoEngine::new(
        password.as_bytes(),
        &BASE64.decode(&meta.salt)?,
        meta.chunk_size as usize,
    )?;
    ensure!(
        crypto.verify_password(&BASE64.decode(&meta.password_check)?),
        "Incorrect password"
    );
    let index_json =
        zeroize::Zeroizing::new(crypto.decrypt_index(&BASE64.decode(&meta.encrypted_index)?)?);
    let mut index: VaultIndex = serde_json::from_slice(&index_json)?;
    ensure!(index.version == 1, "Unsupported vault index");
    let mut paths = BTreeMap::new();
    for entry in &index.dirs {
        register(&mut paths, &entry.path, true)?;
    }
    for entry in &index.files {
        register(&mut paths, &entry.path, false)?;
        ensure!(
            Uuid::parse_str(&entry.id).is_ok(),
            "Invalid encrypted file identifier"
        );
        regular(&data.join(format!("{}.enc", entry.id)), false)?;
    }

    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for e in WalkDir::new(&folder)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            !(e.depth() == 1
                && [VAULT_DATA_DIR, VAULT_META_FILE, OPERATION_LOCK]
                    .iter()
                    .any(|name| e.file_name().to_string_lossy().eq_ignore_ascii_case(name)))
        })
    {
        let e = e?;
        let path = e.path();
        let md = fs::symlink_metadata(path)?;
        ensure!(
            !is_link(&md) && (md.is_file() || md.is_dir()),
            "不支持链接或特殊文件，请先移出: {}",
            path.display()
        );
        let relative = path
            .strip_prefix(&folder)?
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .context("File path is not valid UTF-8")
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        let new_path = register(&mut paths, &relative, md.is_dir())?;
        if md.is_file() {
            files.push(path.to_path_buf());
        } else {
            dirs.push((path.to_path_buf(), new_path));
        }
    }
    if files.is_empty() && !dirs.iter().any(|(_, new)| *new) {
        return Ok(0);
    }

    let mut pending = Pending::default();
    let mut sources = Vec::new();
    let old_count = index.files.len();
    for path in &files {
        let mut source = super::incremental_source::open(path)
            .with_context(|| format!("无法独占新增文件，原文未删除: {}", path.display()))?;
        let id = Uuid::new_v4().to_string();
        let blob = data.join(format!("{id}.enc"));
        // Reserve a unique path; never truncate an existing ciphertext blob.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&blob)?;
        pending.blobs.push(blob.clone());
        let digest = crypto.encrypt_file(path, &blob)?;
        fs::OpenOptions::new().write(true).open(&blob)?.sync_all()?;
        source.verify(&digest)?;
        index
            .files
            .push(build_file_entry(&id, path, &folder, Some(digest))?);
        sources.push(source);
        hook(Stage::AfterBlob)?;
    }
    let new_dirs: Vec<PathBuf> = dirs
        .iter()
        .filter(|(_, new)| *new)
        .map(|(p, _)| p.clone())
        .collect();
    index.dirs.extend(build_dir_entries(&folder, &new_dirs)?);
    let serialized = zeroize::Zeroizing::new(serde_json::to_vec(&index)?);
    meta.encrypted_index = BASE64.encode(crypto.encrypt_index(&serialized)?);
    let bytes = serde_json::to_vec_pretty(&meta)?;
    let primary_temp = stage_meta(&data, &bytes, &mut pending)?;
    let backup_temp = stage_meta(&data, &bytes, &mut pending)?;
    sync_dir(&data)?;
    hook(Stage::BeforePrimary)?;
    replace_synced(&primary_temp, &primary)?;
    pending.committed = true; // Must precede EVERY fallible post-replacement step.
    let finish = (|| -> Result<()> {
        hook(Stage::AfterPrimary)?;
        sync_dir(&folder)?;
        replace_synced(&backup_temp, &backup)?;
        sync_dir(&data)?;
        hook(Stage::BeforeCleanup)?;
        Ok(())
    })();
    finish.context("新索引已提交，但备份或清理准备未完成；新增明文全部保留。请保留整个文件夹，勿直接解密覆盖，先将残留明文移到安全位置")?;

    let mut failures = Vec::new();
    for (path, source) in files.iter().zip(sources) {
        if let Err(err) = source.erase() {
            failures.push(format!("{}: {err:#}", path.display()));
        }
    }
    dirs.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    for (dir, _) in &dirs {
        let _ = fs::remove_dir(dir);
    }
    ensure!(
        failures.is_empty(),
        "新文件已加密，但部分明文清理失败；先将残留明文移到安全位置再解密或继续加密: {}",
        failures.join("; ")
    );
    #[cfg(windows)]
    {
        let _ = set_hidden_attribute(&primary);
    }
    Ok(index.files.len() - old_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const PASSWORD: &str = "incremental-test-password";

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("sv_append_{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, content: &[u8]) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }

        fn locked() -> Self {
            let f = Self::new();
            f.write("old.txt", b"old secret");
            super::super::lock(&f.0, PASSWORD).unwrap();
            f
        }

        fn blobs(&self) -> BTreeMap<String, Vec<u8>> {
            fs::read_dir(self.0.join(VAULT_DATA_DIR))
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|e| e == "enc"))
                .map(|p| {
                    (
                        p.file_name().unwrap().to_string_lossy().into_owned(),
                        fs::read(p).unwrap(),
                    )
                })
                .collect()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn append_preserves_old_ciphertext_and_restores_every_file() {
        let f = Fixture::locked();
        let old_blobs = f.blobs();
        let old_meta = fs::read(f.0.join(VAULT_META_FILE)).unwrap();
        f.write("new/中文.txt", b"new secret");
        f.write("new/empty.bin", b"");
        fs::create_dir_all(f.0.join("new/empty-directory")).unwrap();
        assert_eq!(append(&f.0, PASSWORD).unwrap(), 2);
        assert!(!f.0.join("old.txt").exists());
        assert!(!f.0.join("new/中文.txt").exists());
        for (name, bytes) in &old_blobs {
            assert_eq!(
                &fs::read(f.0.join(VAULT_DATA_DIR).join(name)).unwrap(),
                bytes
            );
        }
        let before: VaultMeta = serde_json::from_slice(&old_meta).unwrap();
        let after: VaultMeta =
            serde_json::from_slice(&fs::read(f.0.join(VAULT_META_FILE)).unwrap()).unwrap();
        assert_eq!(before.salt, after.salt);
        assert_eq!(before.password_check, after.password_check);
        assert_eq!(
            fs::read(f.0.join(VAULT_META_FILE)).unwrap(),
            fs::read(f.0.join(VAULT_DATA_DIR).join(VAULT_META_BACKUP_FILE)).unwrap()
        );
        assert_eq!(append(&f.0, PASSWORD).unwrap(), 0);
        super::super::unlock(&f.0, PASSWORD).unwrap();
        assert_eq!(fs::read(f.0.join("old.txt")).unwrap(), b"old secret");
        assert_eq!(fs::read(f.0.join("new/中文.txt")).unwrap(), b"new secret");
        assert_eq!(fs::read(f.0.join("new/empty.bin")).unwrap(), b"");
        assert!(f.0.join("new/empty-directory").is_dir());
    }

    #[test]
    fn append_wrong_password_does_not_change_any_data() {
        let f = Fixture::locked();
        f.write("new.txt", b"keep me");
        let blobs = f.blobs();
        let meta = fs::read(f.0.join(VAULT_META_FILE)).unwrap();
        assert!(append(&f.0, "incorrect").is_err());
        assert_eq!(f.blobs(), blobs);
        assert_eq!(fs::read(f.0.join(VAULT_META_FILE)).unwrap(), meta);
        assert_eq!(fs::read(f.0.join("new.txt")).unwrap(), b"keep me");
    }

    #[test]
    fn append_refuses_same_path_and_ancestor_conflicts_without_changes() {
        for path in ["old.txt", "OLD.TXT", "old.txt/child.txt"] {
            let f = Fixture::locked();
            f.write(path, b"do not overwrite");
            f.write("safe.txt", b"also preserve");
            let blobs = f.blobs();
            let meta = fs::read(f.0.join(VAULT_META_FILE)).unwrap();
            let err = append(&f.0, PASSWORD).unwrap_err().to_string();
            assert!(err.contains("conflict"), "{err}");
            assert_eq!(f.blobs(), blobs);
            assert_eq!(fs::read(f.0.join(VAULT_META_FILE)).unwrap(), meta);
            assert_eq!(fs::read(f.0.join(path)).unwrap(), b"do not overwrite");
            assert_eq!(fs::read(f.0.join("safe.txt")).unwrap(), b"also preserve");
        }
    }

    #[test]
    fn append_requires_an_existing_vault() {
        let f = Fixture::new();
        f.write("plain.txt", b"keep me");
        assert!(append(&f.0, PASSWORD).is_err());
        assert!(!f.0.join(VAULT_META_FILE).exists());
        assert_eq!(fs::read(f.0.join("plain.txt")).unwrap(), b"keep me");
    }

    #[test]
    fn failures_before_commit_roll_back_only_new_ciphertext() {
        for fail_at in [Stage::AfterBlob, Stage::BeforePrimary] {
            let f = Fixture::locked();
            f.write("new.txt", b"keep me");
            let before = f.blobs();
            let meta = fs::read(f.0.join(VAULT_META_FILE)).unwrap();
            assert!(append_with_hook(&f.0, PASSWORD, |stage| {
                ensure!(stage != fail_at, "injected write failure");
                Ok(())
            })
            .is_err());
            assert_eq!(f.blobs(), before);
            assert_eq!(fs::read(f.0.join(VAULT_META_FILE)).unwrap(), meta);
            assert_eq!(fs::read(f.0.join("new.txt")).unwrap(), b"keep me");
        }
    }

    #[test]
    fn failures_after_commit_keep_new_ciphertext_and_plaintext_recoverable() {
        for fail_at in [Stage::AfterPrimary, Stage::BeforeCleanup] {
            let f = Fixture::locked();
            f.write("new.txt", b"keep me");
            let err = append_with_hook(&f.0, PASSWORD, |stage| {
                ensure!(stage != fail_at, "injected postcommit failure");
                Ok(())
            })
            .unwrap_err();
            assert!(err.to_string().contains("新索引已提交"));
            assert_eq!(f.blobs().len(), 2);
            assert_eq!(fs::read(f.0.join("new.txt")).unwrap(), b"keep me");
            assert!(append(&f.0, PASSWORD)
                .unwrap_err()
                .to_string()
                .contains("conflict"));
            fs::remove_file(f.0.join("new.txt")).unwrap(); // Disposable fixture only.
            super::super::unlock(&f.0, PASSWORD).unwrap();
            assert_eq!(fs::read(f.0.join("new.txt")).unwrap(), b"keep me");
            assert_eq!(fs::read(f.0.join("old.txt")).unwrap(), b"old secret");
        }
    }

    #[test]
    fn operation_lock_excludes_all_mutating_operations_and_is_never_encrypted() {
        let f = Fixture::locked();
        f.write("new.txt", b"keep me");
        let held = operation_lock(&f.0).unwrap();
        assert!(append(&f.0, PASSWORD).is_err());
        assert!(super::super::unlock(&f.0, PASSWORD).is_err());
        assert!(super::super::lock(&f.0, PASSWORD).is_err());
        drop(held);
        assert_eq!(append(&f.0, PASSWORD).unwrap(), 1);
        super::super::unlock(&f.0, PASSWORD).unwrap();
        assert_eq!(fs::metadata(f.0.join(OPERATION_LOCK)).unwrap().len(), 0);
        assert!(scan_folder(&f.0)
            .unwrap()
            .0
            .iter()
            .all(|p| p.file_name().unwrap() != OPERATION_LOCK));
    }

    #[test]
    fn directories_merge_and_file_over_directory_is_rejected() {
        let f = Fixture::new();
        f.write("existing/old.txt", b"old");
        super::super::lock(&f.0, PASSWORD).unwrap();
        f.write("existing", b"conflicting file");
        assert!(append(&f.0, PASSWORD)
            .unwrap_err()
            .to_string()
            .contains("conflict"));
        fs::remove_file(f.0.join("existing")).unwrap();
        f.write("existing/new.txt", b"new");
        assert_eq!(append(&f.0, PASSWORD).unwrap(), 1);
        fs::create_dir_all(f.0.join("empty-only/sub")).unwrap();
        assert_eq!(append(&f.0, PASSWORD).unwrap(), 0);
        super::super::unlock(&f.0, PASSWORD).unwrap();
        assert_eq!(fs::read(f.0.join("existing/old.txt")).unwrap(), b"old");
        assert_eq!(fs::read(f.0.join("existing/new.txt")).unwrap(), b"new");
        assert!(f.0.join("empty-only/sub").is_dir());
    }

    #[test]
    fn unlock_refuses_to_overwrite_new_plaintext() {
        let f = Fixture::locked();
        f.write("old.txt", b"newer unsaved plaintext");
        let before = f.blobs();
        assert!(super::super::unlock(&f.0, PASSWORD).is_err());
        assert_eq!(
            fs::read(f.0.join("old.txt")).unwrap(),
            b"newer unsaved plaintext"
        );
        assert_eq!(f.blobs(), before);
    }

    #[cfg(unix)]
    #[test]
    fn restore_preflight_preserves_unix_name_compatibility() {
        let f = Fixture::new();
        let mut index = VaultIndex {
            version: 1,
            files: vec![],
            dirs: vec![],
        };
        for name in ["a:b", "con", "a", "A"] {
            f.write(name, b"content");
            index
                .files
                .push(build_file_entry("id", &f.0.join(name), &f.0, None).unwrap());
            fs::remove_file(f.0.join(name)).unwrap();
        }
        check_restore_targets(&f.0, &index).unwrap();
    }
}
