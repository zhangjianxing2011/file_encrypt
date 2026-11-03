use serde::{Deserialize, Serialize};

/// Name of the hidden directory that stores encrypted file blobs.
pub const VAULT_DATA_DIR: &str = ".vault_data";

/// Name of the metadata file that stores the encrypted index + KDF params.
pub const VAULT_META_FILE: &str = ".vault_meta";

/// Redundant backup copy of metadata stored inside .vault_data for disaster recovery
pub const VAULT_META_BACKUP_FILE: &str = ".vault_meta.bak";

// ─── On-disk metadata (stored as JSON in .vault_meta) ───────────────

/// Top-level vault metadata. Stored as plaintext JSON so that we can
/// read the salt and password check without knowing the password.
/// The actual file index is encrypted inside `encrypted_index`.
#[derive(Serialize, Deserialize, Debug)]
pub struct VaultMeta {
    /// Format version (currently 1)
    pub version: u32,
    /// Base64-encoded random salt (32 bytes) for Argon2id
    pub salt: String,
    /// Base64-encoded HMAC-SHA256 password check value
    pub password_check: String,
    /// Chunk size used during encryption (bytes)
    pub chunk_size: u32,
    /// Base64-encoded encrypted index: nonce(12) || ciphertext || tag(16)
    pub encrypted_index: String,
}

// ─── Encrypted index payload ────────────────────────────────────────

/// Directory tree index. Serialized to JSON, then encrypted with the
/// index key and stored inside VaultMeta.encrypted_index.
#[derive(Serialize, Deserialize, Debug)]
pub struct VaultIndex {
    pub version: u32,
    pub files: Vec<FileEntry>,
    pub dirs: Vec<DirEntry>,
}

/// A single encrypted file's metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntry {
    /// UUID identifying the encrypted blob (maps to .vault_data/{id}.enc)
    pub id: String,
    /// Original relative path from vault root, normalized to '/' separators
    pub path: String,
    /// Original file size in bytes
    pub size: u64,
    /// Last modified time: seconds since UNIX epoch
    pub modified_secs: i64,
    /// Last modified time: nanosecond component
    pub modified_nanos: u32,
    /// Unix file mode (e.g. 0o644). None on Windows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_mode: Option<u32>,
    /// Windows readonly flag. None on Unix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
    /// SHA-256 hex digest of original plaintext for whole-file end-to-end authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// A directory entry for preserving empty directories and permissions.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirEntry {
    /// Relative path from vault root, normalized to '/' separators
    pub path: String,
    /// Unix directory mode. None on Windows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_mode: Option<u32>,
}
