//! Root key file: generation, loading, and HKDF derivation of the two
//! per-database subkeys (`chain_key`, `anchor_key`) used by Phase 3.5's
//! HMAC-keyed hash chain and external anchor.
//!
//! **No key rotation, by design.** Rotating would mean multi-key
//! verification, a `kid` column on every row, and migration semantics for
//! a chain mid-rotation -- complexity that doesn't earn its weight for a
//! single-user, local-first audit tool with (at the time this was written)
//! zero existing users to migrate. A user who wants a fresh key runs
//! `auditmcp reset --keep-old`, which archives the old chain/key and starts
//! a brand new one. If key rotation is ever revisited, it needs its own
//! design pass, not an incremental patch onto this module.

use crate::hex::hex_encode;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};

const KEY_FILE_VERSION: u32 = 1;
const CHAIN_INFO: &[u8] = b"auditmcp-chain-v1";
const ANCHOR_INFO: &[u8] = b"auditmcp-anchor-v1";

#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    pub version: u32,
    pub created: String,
    pub root_key_hex: String,
    /// The `db_uuid` of the database this key was generated alongside.
    /// Informational only -- the HKDF salt actually used at derivation
    /// time always comes from that database's own `chain_metadata` row,
    /// never from this field, so a key file reused (deliberately or not)
    /// across more than one database cannot silently drift out of sync
    /// with what each chain was actually keyed with.
    pub db_uuid: String,
}

impl KeyFile {
    /// Generates a fresh 32-byte root key using the OS CSPRNG.
    pub fn generate(db_uuid: &str) -> Self {
        use rand::RngCore;
        let mut root_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root_key);
        KeyFile {
            version: KEY_FILE_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            root_key_hex: hex_encode(&root_key),
            db_uuid: db_uuid.to_string(),
        }
    }

    pub fn root_key_bytes(&self) -> anyhow::Result<[u8; 32]> {
        let bytes = hex_decode(&self.root_key_hex)
            .map_err(|e| anyhow::anyhow!("key file has a malformed root_key_hex: {e}"))?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("root key must be 32 bytes, got {}", v.len()))
    }

    /// Derives the `(chain_key, anchor_key)` pair for one database, using
    /// that database's own `chain_metadata.db_uuid` as the HKDF salt. The
    /// salt is what keeps two databases sharing one root key file from
    /// ending up with the same effective chain key -- see the module doc
    /// on `db_uuid`.
    pub fn derive_subkeys(&self, db_uuid_salt: &str) -> anyhow::Result<([u8; 32], [u8; 32])> {
        let root_key = self.root_key_bytes()?;
        let hk = Hkdf::<Sha256>::new(Some(db_uuid_salt.as_bytes()), &root_key);

        let mut chain_key = [0u8; 32];
        hk.expand(CHAIN_INFO, &mut chain_key)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed for chain_key: {e}"))?;

        let mut anchor_key = [0u8; 32];
        hk.expand(ANCHOR_INFO, &mut anchor_key)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed for anchor_key: {e}"))?;

        Ok((chain_key, anchor_key))
    }

    /// `sha256(root_key)`, hex-encoded, truncated to its first 16
    /// characters (64 bits of the digest). Display-only -- safe to share
    /// out-of-band (e.g. pasted into a ticket to confirm "yes, this is the
    /// same key") since it does not reveal the key itself, and never used
    /// as a MAC.
    pub fn fingerprint(&self) -> anyhow::Result<String> {
        use sha2::Digest;
        let root_key = self.root_key_bytes()?;
        let digest = Sha256::digest(root_key);
        Ok(hex_encode(&digest)[..16].to_string())
    }

    /// Loads an existing key file. `None` (not an error) if the file does
    /// not exist -- the caller decides whether that's "generate a new one"
    /// or "refuse to start," which depends on whether a database already
    /// exists.
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read key file {}: {e}", path.display()))?;
        let key: KeyFile = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("key file {} is not valid: {e}", path.display()))?;
        Ok(Some(key))
    }

    /// Writes the key file, creating its parent directory if needed.
    /// Permissions are set to 0600 on the file always, and 0700 on the
    /// parent directory only when this call created it -- `key_path` is
    /// user-configurable, so a pre-existing directory here can be `$HOME`
    /// or a shared project directory, and narrowing one the code did not
    /// create is not this function's call to make. On
    /// Windows, the file's DACL is rewritten to grant only the current
    /// user access, replacing whatever it inherited -- see
    /// `restrict_to_current_user_windows` for why this can't just be a
    /// permission-bits equivalent the way Unix's is.
    ///
    /// The restrictive permissions are applied AT CREATION, not after:
    /// `std::fs::write` creates with umask defaults (typically 0644 --
    /// world-readable) and tightening afterwards leaves a window in which
    /// the root key sits on disk readable by every local process. See
    /// `write_restricted`.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!("key path {} has no parent directory", path.display())
        })?;
        // Whether the directory was ours to tighten is only knowable
        // before `create_dir_all`, which succeeds either way.
        let parent_existed = parent.exists();
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!("failed to create key directory {}: {e}", parent.display())
        })?;

        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| anyhow::anyhow!("failed to set key directory permissions: {e}"))?;
        }
        #[cfg(not(unix))]
        let _ = parent_existed;

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize key file: {e}"))?;
        write_restricted(path, &json)
    }

    /// Atomically copies this key to `dest`: write-to-temp then rename,
    /// same pattern `export.rs` uses for its `--output` writes, so an
    /// interrupted backup never leaves a half-written file at `dest`.
    /// Permissions on the copy are set the same way `save` sets them.
    pub fn backup(&self, dest: &Path) -> anyhow::Result<()> {
        let parent = dest.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "backup destination {} has no parent directory",
                dest.display()
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create backup directory {}: {e}",
                parent.display()
            )
        })?;

        let tmp = dest.with_extension(format!(
            "{}.tmp-{}",
            dest.extension().and_then(|e| e.to_str()).unwrap_or("key"),
            uuid::Uuid::new_v4()
        ));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize key file: {e}"))?;
        if let Err(e) = write_restricted(&tmp, &json) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        std::fs::rename(&tmp, dest).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            anyhow::anyhow!(
                "failed to move backup into place at {}: {e}",
                dest.display()
            )
        })?;
        Ok(())
    }

    /// Loads the key at `path` if present, otherwise generates one and
    /// saves it -- the "no DB, no key" bootstrap case.
    pub fn load_or_generate(path: &Path, db_uuid: &str) -> anyhow::Result<Self> {
        if let Some(key) = Self::load(path)? {
            return Ok(key);
        }
        let key = Self::generate(db_uuid);
        key.save(path)?;
        Ok(key)
    }
}

/// Expands a leading `~` (or `~/...`) against the home directory, the same
/// convention the config's `key_path` string uses. Paths without a leading
/// `~` are returned unchanged.
pub fn expand_tilde(path: &str) -> anyhow::Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        let home = home_dir().ok_or_else(|| {
            anyhow::anyhow!("could not determine home directory to expand '{path}'")
        })?;
        return Ok(home.join(rest));
    }
    if path == "~" {
        return home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory to expand '~'"));
    }
    Ok(PathBuf::from(path))
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Rewrites `path`'s DACL so only the current user has access, replacing
/// whatever it inherited from its parent directory.
///
/// Windows has no permission-bits analogue to Unix's 0600 -- access is
/// governed by a discretionary ACL (DACL) attached to the file itself, not
/// a small integer. A newly created file inherits its DACL from its parent
/// directory, which on a typical machine grants the owning user, the
/// Administrators group, and SYSTEM full control -- broader than the
/// single-user access 0600 gives on Unix, and not tightened by anything
/// `std::fs` exposes. This was a known, permanent gap (not just a race
/// window) on this project's primary target platform until this function:
/// it removes every existing ACL entry and grants exactly one back, to the
/// user running this process.
#[cfg(windows)]
fn restrict_to_current_user_windows(path: &Path) -> anyhow::Result<()> {
    use winapi::um::winnt::{DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    use windows_acl::acl::ACL;
    use windows_acl::helper::{current_user, name_to_sid};

    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("key path {} is not valid UTF-8", path.display()))?;

    let username = current_user()
        .ok_or_else(|| anyhow::anyhow!("could not determine the current Windows user"))?;
    let mut user_sid = name_to_sid(&username, None).map_err(|e| {
        anyhow::anyhow!("failed to resolve SID for user '{username}' (Win32 error {e})")
    })?;

    let mut acl = ACL::from_file_path(path_str, false).map_err(|e| {
        anyhow::anyhow!(
            "failed to open ACL for key file {} (Win32 error {e})",
            path.display()
        )
    })?;

    // Remove every existing entry first -- including the ones just
    // inherited from the parent directory -- so what's left afterward is
    // exactly the one grant added below, not that grant plus whatever was
    // already there.
    let entries = acl.all().map_err(|e| {
        anyhow::anyhow!(
            "failed to enumerate ACL for key file {} (Win32 error {e})",
            path.display()
        )
    })?;
    for mut entry in entries {
        if let Some(sid) = entry.sid.as_mut() {
            acl.remove(sid.as_mut_ptr() as *mut _, None, None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to strip an inherited ACL entry from key file {} (Win32 error {e})",
                        path.display()
                    )
                })?;
        }
    }

    acl.allow(
        user_sid.as_mut_ptr() as *mut _,
        false,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to grant the current user access to key file {} (Win32 error {e})",
            path.display()
        )
    })?;

    Ok(())
}

/// Writes key material to `path` with restrictive permissions in effect
/// FROM THE MOMENT THE FILE EXISTS, closing the TOCTOU window where the
/// plaintext root key sat on disk world-readable between `fs::write` (which
/// creates with umask defaults) and a later permission fix-up.
///
/// - Unix: created via `OpenOptions` with mode 0600, so no readable state
///   ever exists; a post-write `set_permissions` re-asserts 0600 for the
///   pre-existing-file case.
/// - Windows: an EMPTY file is created first, its DACL is rewritten to
///   grant only the current user (`restrict_to_current_user_windows`), and
///   only then is content written -- a racing reader can win only an empty
///   file it cannot reopen.
fn write_restricted(path: &Path, json: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(json.as_bytes()))
            .map_err(|e| anyhow::anyhow!("failed to write key file {}: {e}", path.display()))?;
        // Re-assert for a file that already existed (creation-time modes do
        // not apply to it); idempotent on a freshly created one.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("failed to set key file permissions: {e}"))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        {
            let _unused = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .map_err(|e| {
                    anyhow::anyhow!("failed to create key file {}: {e}", path.display())
                })?;
        } // handle dropped: empty, DACL-restricted file now exists
        restrict_to_current_user_windows(path)?;
        std::fs::write(path, json)
            .map_err(|e| anyhow::anyhow!("failed to write key file {}: {e}", path.display()))
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    // Operates on bytes with an explicit nibble table rather than slicing
    // by byte offset into the string: a corrupt or malicious key file whose
    // `root_key_hex` contains multi-byte characters would otherwise panic
    // on a non-char-boundary slice instead of returning this error.
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = nibble(pair[0])
            .ok_or_else(|| format!("invalid hex character '{}'", pair[0] as char))?;
        let lo = nibble(pair[1])
            .ok_or_else(|| format!("invalid hex character '{}'", pair[1] as char))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_key_path(label: &str) -> PathBuf {
        crate::db::test_support::temp_isolated_dir(label).join("audit.key")
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_narrow_a_directory_it_did_not_create() {
        use std::os::unix::fs::PermissionsExt;

        // A directory the user already had, group-readable on purpose.
        let dir = crate::db::test_support::temp_isolated_dir("keys_preexisting_dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("audit.key");

        Key::generate("db-uuid").save(&path).unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755, "pre-existing directory must keep its mode");
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "the key file itself must still be 0600");

        cleanup_key_path(&path);
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_a_directory_it_creates() {
        use std::os::unix::fs::PermissionsExt;

        let base = crate::db::test_support::temp_isolated_dir("keys_created_dir");
        let dir = base.join("keys");
        let path = dir.join("audit.key");

        Key::generate("db-uuid").save(&path).unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "a directory we created is ours to restrict"
        );

        cleanup_key_path(&path);
        let _ = std::fs::remove_dir(&base);
    }

    /// Removes a key file and the isolated directory `temp_key_path`
    /// created for it.
    fn cleanup_key_path(path: &Path) {
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[test]
    fn generate_produces_a_32_byte_root_key() {
        let key = KeyFile::generate("db-1");
        assert_eq!(key.root_key_bytes().unwrap().len(), 32);
    }

    #[test]
    fn two_generated_keys_are_never_equal() {
        let a = KeyFile::generate("db-1");
        let b = KeyFile::generate("db-1");
        assert_ne!(a.root_key_hex, b.root_key_hex);
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = temp_key_path("roundtrip");
        let key = KeyFile::generate("db-1");
        key.save(&path).unwrap();

        let loaded = KeyFile::load(&path).unwrap().unwrap();
        assert_eq!(loaded.root_key_hex, key.root_key_hex);
        assert_eq!(loaded.db_uuid, "db-1");

        cleanup_key_path(&path);
    }

    #[test]
    fn load_of_missing_file_is_none_not_error() {
        let path = temp_key_path("missing");
        assert!(KeyFile::load(&path).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn saved_key_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_key_path("perms");
        KeyFile::generate("db-1").save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let parent_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o700);

        cleanup_key_path(&path);
    }

    /// Windows equivalent of `saved_key_file_has_0600_permissions`: after
    /// `save`, the file's DACL must grant access to exactly one SID (the
    /// current user), not the broader set inherited from the parent
    /// directory. This is the fix for the gap `save`'s doc comment used to
    /// describe explicitly ("no equivalent tightening applied here").
    #[cfg(windows)]
    #[test]
    fn saved_key_file_restricts_the_acl_to_the_current_user() {
        use windows_acl::acl::ACL;
        use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

        let path = temp_key_path("acl");
        KeyFile::generate("db-1").save(&path).unwrap();

        let acl = ACL::from_file_path(path.to_str().unwrap(), false).unwrap();
        let entries = acl.all().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the DACL must contain exactly one entry after save: {:?}",
            entries.iter().map(|e| &e.string_sid).collect::<Vec<_>>()
        );

        let username = current_user().unwrap();
        let mut expected_sid = name_to_sid(&username, None).unwrap();
        let expected_string_sid = sid_to_string(expected_sid.as_mut_ptr() as *mut _).unwrap();
        assert_eq!(
            entries[0].string_sid, expected_string_sid,
            "the sole entry must belong to the current user"
        );

        cleanup_key_path(&path);
    }

    /// The same root key salted with two different `db_uuid`s must derive
    /// two different chain keys -- otherwise the salt is decorative and
    /// key reuse across databases would produce colliding chain keys.
    #[test]
    fn different_db_uuid_salts_derive_different_chain_keys() {
        let key = KeyFile::generate("ignored");
        let (chain_a, anchor_a) = key.derive_subkeys("db-a").unwrap();
        let (chain_b, anchor_b) = key.derive_subkeys("db-b").unwrap();
        assert_ne!(chain_a, chain_b);
        assert_ne!(anchor_a, anchor_b);
    }

    #[test]
    fn chain_key_and_anchor_key_from_the_same_root_differ() {
        let key = KeyFile::generate("db-1");
        let (chain_key, anchor_key) = key.derive_subkeys("db-1").unwrap();
        assert_ne!(chain_key, anchor_key);
    }

    #[test]
    fn derivation_is_deterministic() {
        let key = KeyFile::generate("db-1");
        let (chain_a, anchor_a) = key.derive_subkeys("db-1").unwrap();
        let (chain_b, anchor_b) = key.derive_subkeys("db-1").unwrap();
        assert_eq!(chain_a, chain_b);
        assert_eq!(anchor_a, anchor_b);
    }

    #[test]
    fn fingerprint_does_not_leak_the_key_and_is_stable() {
        let key = KeyFile::generate("db-1");
        let fp1 = key.fingerprint().unwrap();
        let fp2 = key.fingerprint().unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
        assert!(!fp1.contains(&key.root_key_hex));
    }

    #[test]
    fn expand_tilde_replaces_leading_home_reference() {
        let expanded = expand_tilde("~/.auditmcp/keys/audit.key").unwrap();
        assert!(expanded.is_absolute());
        assert!(!expanded.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn backup_writes_a_loadable_copy() {
        let dest = temp_key_path("backup");
        let key = KeyFile::generate("db-1");
        key.backup(&dest).unwrap();

        let loaded = KeyFile::load(&dest).unwrap().unwrap();
        assert_eq!(loaded.root_key_hex, key.root_key_hex);

        cleanup_key_path(&dest);
    }

    #[test]
    fn backup_never_leaves_a_temp_file_behind() {
        let dest = temp_key_path("backup_notemp");
        KeyFile::generate("db-1").backup(&dest).unwrap();

        let parent = dest.parent().unwrap();
        let stray_temp = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("tmp-"));
        assert!(!stray_temp, "backup must not leave a stray temp file");

        cleanup_key_path(&dest);
    }

    #[test]
    fn expand_tilde_leaves_absolute_paths_untouched() {
        let p = if cfg!(windows) {
            "C:\\abs\\path"
        } else {
            "/abs/path"
        };
        let expanded = expand_tilde(p).unwrap();
        assert_eq!(expanded, PathBuf::from(p));
    }

    /// A malformed `root_key_hex` must produce an error, never the panic a
    /// byte-offset slice into multi-byte characters produced. This value is
    /// DB/file-controlled, so it is hostile input by the project's own
    /// threat model.
    #[test]
    fn hex_decode_rejects_multibyte_and_non_hex_without_panicking() {
        // '€' is 3 bytes; even total length, but a naive 2-byte slice
        // straddles its interior.
        assert!(hex_decode("€100").is_err());
        assert!(hex_decode("€1").is_err());
        // '+' parses as numeric sign for from_str_radix but is not hex.
        assert!(hex_decode("+a0a").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err()); // odd length
                                             // Uppercase stays accepted (it was before).
        assert_eq!(hex_decode("DEADBEEF"), Ok(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_decode(""), Ok(Vec::new()));
    }

    #[test]
    fn key_file_with_multibyte_hex_is_an_error_not_a_panic() {
        let mut key = KeyFile::generate("db-1");
        key.root_key_hex = "€100".to_string();
        assert!(key.root_key_bytes().is_err());
    }
}
