use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce, Tag,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::Hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Constants ──────────────────────────────────────────────────────

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

// Argon2id parameters: ~0.5-1s on modern hardware, resistant to GPU attacks
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_M_COST: u32 = 65536; // 64 MB memory
const ARGON2_P_COST: u32 = 4; // 4 parallel lanes

// HKDF context strings for domain separation
const INDEX_KEY_INFO: &[u8] = b"securevault-index-key-v1";
const DATA_KEY_INFO: &[u8] = b"securevault-data-key-v1";
const HMAC_KEY_INFO: &[u8] = b"securevault-hmac-key-v1";
const PASSWORD_CHECK_MSG: &[u8] = b"securevault-password-check-v1";

type HmacSha256 = Hmac<Sha256>;

/// Result of file encryption / decryption containing whole-file size and SHA-256 digest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    pub size: u64,
    pub sha256: [u8; 32],
}

impl FileDigest {
    pub fn sha256_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.sha256 {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

// ─── CryptoEngine ───────────────────────────────────────────────────

/// Core cryptographic engine. Holds derived sub-keys in memory and
/// provides encrypt/decrypt operations. All key material is securely
/// zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CryptoEngine {
    index_key: [u8; KEY_LEN],
    data_key: [u8; KEY_LEN],
    hmac_key: [u8; KEY_LEN],
    #[zeroize(skip)]
    chunk_size: usize,
}

impl CryptoEngine {
    /// Create a new engine by deriving keys from password + salt.
    ///
    /// Internally:
    ///   master_key  = Argon2id(password, salt)
    ///   index_key   = HKDF(master_key, "securevault-index-key-v1")
    ///   data_key    = HKDF(master_key, "securevault-data-key-v1")
    ///   hmac_key    = HKDF(master_key, "securevault-hmac-key-v1")
    pub fn new(password: &[u8], salt: &[u8], chunk_size: usize) -> Result<Self> {
        // 1. Derive master key with Argon2id
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
            .map_err(|e| anyhow!("Invalid Argon2 params: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut master_key = [0u8; KEY_LEN];
        argon2
            .hash_password_into(password, salt, &mut master_key)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

        // 2. Derive sub-keys with HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(salt), &master_key);

        let mut index_key = [0u8; KEY_LEN];
        let mut data_key = [0u8; KEY_LEN];
        let mut hmac_key = [0u8; KEY_LEN];

        hk.expand(INDEX_KEY_INFO, &mut index_key)
            .map_err(|_| anyhow!("HKDF expand failed for index key"))?;
        hk.expand(DATA_KEY_INFO, &mut data_key)
            .map_err(|_| anyhow!("HKDF expand failed for data key"))?;
        hk.expand(HMAC_KEY_INFO, &mut hmac_key)
            .map_err(|_| anyhow!("HKDF expand failed for HMAC key"))?;

        // 3. Zeroize master key immediately
        master_key.zeroize();

        Ok(Self {
            index_key,
            data_key,
            hmac_key,
            chunk_size,
        })
    }

    /// Generate a cryptographically secure random salt.
    pub fn generate_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Compute a password check value (HMAC of known message).
    /// Stored in vault metadata for fast password verification
    /// without needing to decrypt any file data.
    pub fn password_check(&self) -> Vec<u8> {
        use hmac::Mac;
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).expect("HMAC key length is always valid");
        mac.update(PASSWORD_CHECK_MSG);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify a password check value using constant-time comparison.
    pub fn verify_password(&self, stored_check: &[u8]) -> bool {
        let computed = self.password_check();
        constant_time_eq(&computed, stored_check)
    }

    // ─── In-memory encryption (for vault index) ─────────────────

    /// Encrypt data in memory. Returns: nonce(12) || ciphertext || tag(16).
    pub fn encrypt_index(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_aead(&self.index_key, plaintext)
    }

    /// Decrypt data in memory.
    pub fn decrypt_index(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_aead(&self.index_key, ciphertext)
    }

    // ─── Streaming file encryption ──────────────────────────────

    /// Encrypt a file using streaming chunked AES-256-GCM with in-place buffer reuse.
    /// Returns the original file size and SHA-256 digest for whole-file end-to-end authentication.
    ///
    /// Output format:
    /// ```text
    /// [4 bytes] chunk_size (u32 LE)
    /// For each chunk:
    ///   [4 bytes] payload_len (u32 LE)
    ///   [12 bytes] nonce
    ///   [variable] ciphertext
    ///   [16 bytes] GCM tag
    /// ```
    pub fn encrypt_file(&self, src: &Path, dst: &Path) -> Result<FileDigest> {
        let src_file = File::open(src)
            .map_err(|e| anyhow!("Cannot open source file '{}': {}", src.display(), e))?;
        let mut reader = BufReader::with_capacity(self.chunk_size, src_file);

        let dst_file = File::create(dst)
            .map_err(|e| anyhow!("Cannot create encrypted file '{}': {}", dst.display(), e))?;
        let mut writer = BufWriter::with_capacity(self.chunk_size + 1024, dst_file);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.data_key));

        // Write chunk size header
        writer.write_all(&(self.chunk_size as u32).to_le_bytes())?;

        // Pre-allocate a single reusable buffer to avoid reallocations in the chunk loop
        let mut buf = vec![0u8; self.chunk_size];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut hasher = Sha256::new();
        let mut total_plain_bytes: u64 = 0;

        let res: Result<()> = (|| {
            loop {
                let bytes_read = read_fill(&mut reader, &mut buf)?;
                if bytes_read == 0 {
                    break;
                }

                // Update SHA-256 with original plaintext chunk before in-place encryption
                hasher.update(&buf[..bytes_read]);
                total_plain_bytes += bytes_read as u64;

                // Random nonce per chunk
                rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                // In-place encryption: encrypts buf[..bytes_read] in-place and returns detached tag
                let tag = cipher
                    .encrypt_in_place_detached(nonce, b"", &mut buf[..bytes_read])
                    .map_err(|_| anyhow!("Chunk encryption failed"))?;

                // Write: payload_len + nonce + ciphertext + tag
                let payload_len = (NONCE_LEN + bytes_read + TAG_LEN) as u32;
                writer.write_all(&payload_len.to_le_bytes())?;
                writer.write_all(&nonce_bytes)?;
                writer.write_all(&buf[..bytes_read])?;
                writer.write_all(tag.as_slice())?;
            }

            writer.flush()?;
            Ok(())
        })();

        if let Err(e) = res {
            drop(writer);
            let _ = std::fs::remove_file(dst);
            return Err(e);
        }

        let sha256_bytes: [u8; 32] = hasher.finalize().into();
        Ok(FileDigest {
            size: total_plain_bytes,
            sha256: sha256_bytes,
        })
    }

    /// Decrypt a file with in-place buffer reuse, validating against expected size and SHA-256.
    /// If any error occurs or integrity verification fails, the destination file is immediately deleted
    /// to prevent leaving behind corrupted or partial plaintext.
    pub fn decrypt_file_authenticated(
        &self,
        src: &Path,
        dst: &Path,
        expected_size: Option<u64>,
        expected_sha256_hex: Option<&str>,
    ) -> Result<FileDigest> {
        let src_file = File::open(src)
            .map_err(|e| anyhow!("Cannot open encrypted file '{}': {}", src.display(), e))?;
        let mut reader = BufReader::with_capacity(self.chunk_size + 1024, src_file);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.data_key));

        // Read chunk size header
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        let chunk_size = u32::from_le_bytes(header) as usize;

        let dst_file = std::fs::OpenOptions::new().write(true).create_new(true).open(dst)
            .map_err(|e| anyhow!("Cannot create output file '{}': {}", dst.display(), e))?;
        let mut writer = BufWriter::with_capacity(chunk_size, dst_file);

        // Pre-allocate reusable buffers for in-place decryption
        let mut buf = vec![0u8; chunk_size];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut tag_bytes = [0u8; TAG_LEN];
        let mut hasher = Sha256::new();
        let mut total_plain_bytes: u64 = 0;

        let res: Result<FileDigest> = (|| {
            loop {
                // Read payload length
                let mut len_bytes = [0u8; 4];
                match reader.read_exact(&mut len_bytes) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e.into()),
                }
                let payload_len = u32::from_le_bytes(len_bytes) as usize;

                if payload_len < NONCE_LEN + TAG_LEN {
                    anyhow::bail!("Corrupted encrypted chunk: payload too small");
                }

                // Read nonce
                reader.read_exact(&mut nonce_bytes)?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                // Read ciphertext (payload_len - NONCE_LEN - TAG_LEN)
                let data_len = payload_len - NONCE_LEN - TAG_LEN;
                if buf.len() < data_len {
                    buf.resize(data_len, 0);
                }
                reader.read_exact(&mut buf[..data_len])?;

                // Read 16-byte tag
                reader.read_exact(&mut tag_bytes)?;
                let tag = Tag::from_slice(&tag_bytes);

                // In-place decryption directly in reusable buffer
                cipher
                    .decrypt_in_place_detached(nonce, b"", &mut buf[..data_len], tag)
                    .map_err(|_| anyhow!("Decryption failed: data corrupted or wrong password"))?;

                // Feed decrypted plaintext to SHA-256 for whole-file integrity authentication
                hasher.update(&buf[..data_len]);
                total_plain_bytes += data_len as u64;

                writer.write_all(&buf[..data_len])?;
            }

            // Whole-file size authentication
            if let Some(exp_size) = expected_size {
                if total_plain_bytes != exp_size {
                    anyhow::bail!(
                        "File integrity check failed: decrypted size mismatch (expected {} bytes, got {})",
                        exp_size,
                        total_plain_bytes
                    );
                }
            }

            let sha256_bytes: [u8; 32] = hasher.finalize().into();
            let digest = FileDigest {
                size: total_plain_bytes,
                sha256: sha256_bytes,
            };

            // Whole-file SHA-256 authentication
            if let Some(exp_sha256) = expected_sha256_hex {
                let computed_hex = digest.sha256_hex();
                if !computed_hex.eq_ignore_ascii_case(exp_sha256) {
                    anyhow::bail!(
                        "File integrity check failed: SHA-256 mismatch (tampered or truncated data)"
                    );
                }
            }

            writer.flush()?;
            Ok(digest)
        })();

        if let Err(e) = res {
            // Drop writer to release file handle on Windows/macOS/Linux, then delete partial plaintext
            drop(writer);
            let _ = std::fs::remove_file(dst);
            return Err(e);
        }

        res
    }

    /// Decrypt a file using streaming chunked AES-256-GCM.
    #[allow(dead_code)]
    pub fn decrypt_file(&self, src: &Path, dst: &Path) -> Result<FileDigest> {
        self.decrypt_file_authenticated(src, dst, None, None)
    }
}

// ─── Low-level helpers ──────────────────────────────────────────────

/// Encrypt with AES-256-GCM. Returns nonce || ciphertext || tag.
fn encrypt_aead(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt with AES-256-GCM. Input: nonce || ciphertext || tag.
fn decrypt_aead(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        anyhow::bail!("Encrypted data too short ({} bytes)", data.len());
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let ciphertext = &data[NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: wrong password or corrupted data"))
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Read into buf, retrying on partial reads until buf is full or EOF.
fn read_fill(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_password_check_roundtrip() {
        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, DEFAULT_CHUNK_SIZE).unwrap();
        let check = engine.password_check();
        assert!(engine.verify_password(&check));
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = CryptoEngine::generate_salt();
        let engine1 = CryptoEngine::new(b"correct-password", &salt, DEFAULT_CHUNK_SIZE).unwrap();
        let check = engine1.password_check();

        let engine2 = CryptoEngine::new(b"wrong-password!!", &salt, DEFAULT_CHUNK_SIZE).unwrap();
        assert!(!engine2.verify_password(&check));
    }

    #[test]
    fn test_index_encrypt_decrypt() {
        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, DEFAULT_CHUNK_SIZE).unwrap();

        let plaintext = b"Hello, this is the vault index data!";
        let encrypted = engine.encrypt_index(plaintext).unwrap();
        let decrypted = engine.decrypt_index(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_file_encrypt_decrypt() {
        let dir = std::env::temp_dir().join("securevault_test_crypto");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let src = dir.join("original.txt");
        let enc = dir.join("encrypted.enc");
        let dec = dir.join("decrypted.txt");

        // Create test file with known content
        let content = b"The quick brown fox jumps over the lazy dog.\n".repeat(1000);
        fs::write(&src, &content).unwrap();

        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, 4096).unwrap(); // small chunks

        engine.encrypt_file(&src, &enc).unwrap();
        engine.decrypt_file(&enc, &dec).unwrap();

        let result = fs::read(&dec).unwrap();
        assert_eq!(content, result.as_slice());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_never_truncates_an_existing_output() {
        let dir = std::env::temp_dir().join(format!("sv_existing_output_{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let src = dir.join("input.enc");
        let dst = dir.join("existing.txt");
        fs::write(&src, b"").unwrap();
        fs::write(&dst, b"newer plaintext").unwrap();
        let engine = CryptoEngine { index_key: [0; 32], data_key: [0; 32], hmac_key: [0; 32], chunk_size: 1024 };
        assert!(engine.decrypt_file(&src, &dst).is_err());
        let remaining = fs::read(&dst).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(remaining, b"newer plaintext");
    }

    #[test]
    fn test_empty_file_encrypt_decrypt() {
        let dir = std::env::temp_dir().join("securevault_test_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let src = dir.join("empty.txt");
        let enc = dir.join("empty.enc");
        let dec = dir.join("empty_out.txt");

        File::create(&src).unwrap();

        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, DEFAULT_CHUNK_SIZE).unwrap();

        engine.encrypt_file(&src, &enc).unwrap();
        engine.decrypt_file(&enc, &dec).unwrap();

        assert_eq!(fs::read(&dec).unwrap().len(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_large_file_encrypt_decrypt() {
        let dir = std::env::temp_dir().join("securevault_test_large");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let src = dir.join("large.bin");
        let enc = dir.join("large.enc");
        let dec = dir.join("large_out.bin");

        // 3.5 MB file (tests partial last chunk)
        let mut f = File::create(&src).unwrap();
        let chunk = vec![0xABu8; 1024];
        for _ in 0..(3584) {
            f.write_all(&chunk).unwrap();
        }
        f.flush().unwrap();
        drop(f);

        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, DEFAULT_CHUNK_SIZE).unwrap();

        engine.encrypt_file(&src, &enc).unwrap();
        engine.decrypt_file(&enc, &dec).unwrap();

        assert_eq!(fs::read(&src).unwrap(), fs::read(&dec).unwrap());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_integrity_tamper_detection() {
        let dir = std::env::temp_dir().join("securevault_test_tamper");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let src = dir.join("secret.txt");
        let enc = dir.join("secret.enc");
        let dec = dir.join("secret_out.txt");

        fs::write(&src, b"Confidential information that must not be tampered with").unwrap();

        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, DEFAULT_CHUNK_SIZE).unwrap();

        let digest = engine.encrypt_file(&src, &enc).unwrap();

        // Tamper with a byte inside encrypted file (flip tag bits)
        let mut enc_bytes = fs::read(&enc).unwrap();
        let last_idx = enc_bytes.len() - 1;
        enc_bytes[last_idx] ^= 0xFF;
        fs::write(&enc, &enc_bytes).unwrap();

        // Decryption must fail
        let res = engine.decrypt_file_authenticated(
            &enc,
            &dec,
            Some(digest.size),
            Some(&digest.sha256_hex()),
        );
        assert!(res.is_err());
        // Cleaned up! Corrupted plaintext must NOT remain on disk
        assert!(!dec.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_truncation_detection() {
        let dir = std::env::temp_dir().join("securevault_test_truncation");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let src = dir.join("large.bin");
        let enc = dir.join("large.enc");
        let dec = dir.join("large_out.bin");

        // 3 chunks of 1KB
        let data = vec![0x42u8; 3072];
        fs::write(&src, &data).unwrap();

        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(b"test-password-123", &salt, 1024).unwrap();

        let digest = engine.encrypt_file(&src, &enc).unwrap();

        // Cut off half of the encrypted file to simulate truncation attack
        let enc_bytes = fs::read(&enc).unwrap();
        let truncated = &enc_bytes[..enc_bytes.len() / 2];
        fs::write(&enc, truncated).unwrap();

        let res = engine.decrypt_file_authenticated(
            &enc,
            &dec,
            Some(digest.size),
            Some(&digest.sha256_hex()),
        );
        assert!(res.is_err());
        // Must be cleanly deleted so no truncated plaintext leaks
        assert!(!dec.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_chinese_password_derivation() {
        let password = "这是中文加密密钥123456!@#";
        let salt = CryptoEngine::generate_salt();
        let engine = CryptoEngine::new(password.as_bytes(), &salt, DEFAULT_CHUNK_SIZE).unwrap();

        let data = b"Hello Chinese password test content";
        let ciphertext = engine.encrypt_index(data).unwrap();
        let decrypted = engine.decrypt_index(&ciphertext).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }
}
