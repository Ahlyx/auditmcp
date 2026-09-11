//! Phase 3.5 bootstrap: decides, once at `auditmcp run` startup, whether a
//! database's chain is a fresh HMAC-keyed one or an existing HMAC-keyed
//! one -- and enforces the refuse-to-start rules that make the HMAC key
//! meaningful.
//!
//! There is no third answer. A database whose `chain_metadata` cannot
//! establish that it is HMAC-protected is refused, not run unkeyed: the
//! legacy scheme is forgeable by anyone (it has no key), so continuing
//! under it turned the whole protection into something a single `DELETE`
//! could switch off.
//!
//! This is deliberately the ONLY place that makes this decision. Splitting
//! "is this chain legacy or HMAC" logic between `run` and `verify` would
//! let them disagree about what a given database is, which defeats the
//! entire point of a keyed chain: two different notions of "genesis" is
//! exactly the kind of asymmetry an attacker exploits.
//!
//! See the bootstrap table in `auditmcp-phase-3.5-chain-hardening.md`:
//!
//! | Situation                                    | Behavior                    |
//! |-----------------------------------------------|-----------------------------|
//! | No DB, no key                                  | Generate key, fresh HMAC chain |
//! | DB exists, key missing                         | Refuse to start              |
//! | DB exists, key present, first-row HMAC fails   | Refuse to start              |
//! | DB exists, key present, first-row HMAC verifies| Proceed                      |
//! | DB has rows but no valid `chain_metadata`      | Refuse to start (tamper)     |

use crate::db::{self, HashKey};
use crate::keys::KeyFile;
use std::path::Path;

/// What a database's chain turned out to be, resolved once at startup and
/// carried through the rest of the session (writer thread, heartbeat task,
/// anchor task).
#[derive(Debug)]
pub enum ChainMode {
    /// A fresh or pre-existing Phase 3.5 chain. `db_uuid` is this chain's
    /// permanent HKDF salt; `heartbeat_cadence_*` is the range fixed at
    /// this chain's genesis (see `db::write_chain_metadata_genesis` for
    /// why that range can never be changed after the fact).
    Hmac {
        chain_key: [u8; 32],
        anchor_key: [u8; 32],
        heartbeat_cadence_min_secs: u64,
        heartbeat_cadence_max_secs: u64,
    },
}

impl ChainMode {
    pub fn hash_key(&self) -> HashKey {
        match self {
            ChainMode::Hmac { chain_key, .. } => HashKey::Hmac(*chain_key),
        }
    }

    /// This chain's anchor key. Every chain a session can run against is
    /// HMAC-protected now, so this is always `Some`; the `Option` is kept
    /// so callers that read "no anchor key" as "skip the anchor" need no
    /// change.
    pub fn anchor_key(&self) -> Option<[u8; 32]> {
        match self {
            ChainMode::Hmac { anchor_key, .. } => Some(*anchor_key),
        }
    }

    /// The heartbeat cadence range this session should use: always the
    /// range fixed at this chain's genesis and covered by the metadata
    /// HMAC (see `db::write_chain_metadata_genesis`), never the live
    /// config, which anyone able to edit the database can edit too.
    pub fn heartbeat_cadence(&self) -> (u64, u64) {
        match self {
            ChainMode::Hmac {
                heartbeat_cadence_min_secs,
                heartbeat_cadence_max_secs,
                ..
            } => (*heartbeat_cadence_min_secs, *heartbeat_cadence_max_secs),
        }
    }
}

/// Resolves a database's `ChainMode`, generating a root key and/or genesis
/// `chain_metadata` if this is truly a brand-new database. Must be called
/// before `db::spawn_writer_with_key` so the writer thread inserts under
/// the correct scheme from row 1.
///
/// `heartbeat_cadence_{min,max}_secs` are only consulted for a brand-new
/// chain (they become that chain's permanent, genesis-fixed range); an
/// existing chain's range comes back out of its own `chain_metadata`
/// instead, via `ChainMode::Hmac`.
pub fn bootstrap(
    db_path: &Path,
    key_path: &Path,
    default_heartbeat_cadence_min_secs: u64,
    default_heartbeat_cadence_max_secs: u64,
) -> anyhow::Result<ChainMode> {
    // Checked BEFORE opening: opening (via `db::open_for_write`) creates
    // the file and schema if absent, which would make "did the file exist
    // before we touched it" unobservable afterward.
    let db_existed = db_path.exists();

    let mut conn = db::open_for_write(db_path)?;

    if !db_existed {
        // "No DB, no key" and "no DB, key present" both land here: either
        // way this is a fresh chain, and a pre-existing key file (e.g. the
        // user pointed a new config at a key_path they already had) is
        // reused rather than treated as a conflict -- there is no
        // "wrong key" concept until a chain exists to disagree with it.
        //
        // If genesis fails after we created the file, remove what we just
        // created: leaving a half-initialized database behind means every
        // later start refuses it (no `chain_metadata`), which is safe but
        // needs a manual `reset` to clear. Failing loudly now keeps the
        // bootstrap table honest.
        match bootstrap_fresh_chain(
            &mut conn,
            key_path,
            default_heartbeat_cadence_min_secs,
            default_heartbeat_cadence_max_secs,
        ) {
            Ok(mode) => Ok(mode),
            Err(e) => {
                let _ = std::fs::remove_file(db_path);
                let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
                let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
                Err(e)
            }
        }
    } else {
        classify_existing_chain(&conn, key_path, db_path)
    }
}

/// The `!db_existed` branch of `bootstrap`: new uuid, new (or reused) key,
/// genesis metadata in one transaction.
fn bootstrap_fresh_chain(
    conn: &mut rusqlite::Connection,
    key_path: &Path,
    heartbeat_cadence_min_secs: u64,
    heartbeat_cadence_max_secs: u64,
) -> anyhow::Result<ChainMode> {
    let db_uuid = uuid::Uuid::new_v4().to_string();
    let key = KeyFile::load_or_generate(key_path, &db_uuid)?;
    let (chain_key, anchor_key) = key.derive_subkeys(&db_uuid)?;
    db::write_chain_metadata_genesis(
        conn,
        &chain_key,
        &db_uuid,
        heartbeat_cadence_min_secs,
        heartbeat_cadence_max_secs,
    )?;
    Ok(ChainMode::Hmac {
        chain_key,
        anchor_key,
        heartbeat_cadence_min_secs,
        heartbeat_cadence_max_secs,
    })
}

fn classify_existing_chain(
    conn: &rusqlite::Connection,
    key_path: &Path,
    _db_path: &Path,
) -> anyhow::Result<ChainMode> {
    let metadata = db::read_chain_metadata(conn)?;
    match metadata {
        Some(m) if m.hmac_version.as_deref() == Some("1") => {
            let key = KeyFile::load(key_path)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "this database is HMAC-protected (Phase 3.5) but its chain key is \
                     missing at {} -- refusing to start. Without the key, `run` cannot \
                     produce a valid chain and `verify` cannot check the existing one. \
                     If this key file was intentionally lost or replaced, the only \
                     supported path is `auditmcp reset --keep-old`.",
                    key_path.display()
                )
            })?;
            let (chain_key, anchor_key) = key.derive_subkeys(&m.db_uuid)?;

            // `chain_metadata` is a plain table, not part of the hash
            // chain -- see `db::verify_chain_metadata_hmac`. A mismatch
            // here means the table was edited directly (a lowered
            // heartbeat cadence, a flipped hmac_version) and is exactly as
            // severe as a broken row hash, so it refuses to start the same
            // way a first-row HMAC failure does.
            if !db::verify_chain_metadata_hmac(conn, &chain_key, &m)? {
                return Err(anyhow::anyhow!(
                    "this database's chain_metadata failed HMAC verification -- \
                     refusing to start. chain_metadata (hmac_version, heartbeat \
                     cadence, db_uuid) is not covered by the tool_calls hash chain \
                     itself, so it carries its own HMAC computed at genesis; a \
                     mismatch means it was edited directly rather than produced by \
                     `auditmcp run`/`reset`. The only supported recovery is \
                     `auditmcp reset --keep-old`."
                ));
            }

            verify_first_row(conn, &chain_key).map_err(|e| {
                anyhow::anyhow!(
                    "HMAC verification of the first chain row failed with the key at {} -- \
                     refusing to start. This usually means the wrong key file is in use, or \
                     the key file is corrupted. Underlying error: {e}",
                    key_path.display()
                )
            })?;

            Ok(ChainMode::Hmac {
                chain_key,
                anchor_key,
                heartbeat_cadence_min_secs: m.heartbeat_cadence_min_secs.unwrap_or(30),
                heartbeat_cadence_max_secs: m.heartbeat_cadence_max_secs.unwrap_or(90),
            })
        }
        Some(m) if m.hmac_version.is_some() => Err(anyhow::anyhow!(
            "this database's chain_metadata declares hmac_version {:?}, which this \
             build of auditmcp does not know how to verify or extend. Refusing to \
             start rather than write rows under an assumption that may be wrong.",
            m.hmac_version
        )),
        // Reached when `chain_metadata` is absent entirely, or present but
        // missing `hmac_version`. This used to warn and continue on the
        // unkeyed legacy scheme, which made the protection opt-out:
        // deleting one row dropped `run` into Legacy and appended unkeyed
        // rows, and the metadata-HMAC guard meant to catch exactly that
        // lives inside the `hmac_version == "1"` arm, so it never ran. A
        // database that cannot prove which scheme it was written under
        // gets no benefit of the doubt.
        _ => Err(anyhow::anyhow!(
            "this database has no usable chain_metadata (no hmac_version), so the \
             hashing scheme its rows were written under cannot be established. \
             Refusing to start. This is either a pre-3.5 database, which is no longer \
             supported in place, or a chain_metadata table that was edited or \
             truncated. Either way the supported path is `auditmcp reset --keep-old`, \
             which archives what is there and starts a fresh HMAC-protected chain."
        )),
    }
}

/// Recomputes the first row's HMAC (chaining from `db::GENESIS_PREV_HASH`)
/// and compares it against what's stored. An empty table (metadata written
/// but no tool_calls row yet -- e.g. a process crashed between genesis and
/// its first insert) has nothing to check and is treated as verified.
///
/// Walks the whole chain rather than only row 1: cheap at startup (this
/// runs once, not per-row), and it means a chain that was tampered with
/// anywhere is caught here rather than only surfacing later via `verify`.
fn verify_first_row(conn: &rusqlite::Connection, chain_key: &[u8; 32]) -> anyhow::Result<()> {
    match db::verify_chain_with_key(conn, &HashKey::Hmac(*chain_key))? {
        Ok(_) => Ok(()),
        Err(issue) => Err(anyhow::anyhow!("{issue}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::{remove_db_files, temp_db_path};

    fn temp_key_path(label: &str) -> std::path::PathBuf {
        crate::db::test_support::temp_isolated_dir(label).join("audit.key")
    }

    struct Fixture {
        db_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            Fixture {
                db_path: temp_db_path(label),
                key_path: temp_key_path(label),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            remove_db_files(&self.db_path);
            let _ = std::fs::remove_file(&self.key_path);
            if let Some(parent) = self.key_path.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }

    #[test]
    fn fresh_database_generates_a_key_and_hmac_metadata() {
        let fx = Fixture::new("fresh");
        assert!(!fx.db_path.exists());
        assert!(!fx.key_path.exists());

        let mode = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();
        assert!(fx.key_path.exists(), "a key file must be generated");
        match mode {
            ChainMode::Hmac {
                heartbeat_cadence_min_secs,
                heartbeat_cadence_max_secs,
                ..
            } => {
                assert_eq!(heartbeat_cadence_min_secs, 30);
                assert_eq!(heartbeat_cadence_max_secs, 90);
            }
        }

        let conn = db::open_readonly(&fx.db_path).unwrap();
        let meta = db::read_chain_metadata(&conn).unwrap().unwrap();
        assert_eq!(meta.hmac_version.as_deref(), Some("1"));
    }

    #[test]
    fn reopening_an_hmac_chain_with_the_same_key_succeeds() {
        let fx = Fixture::new("reopen");
        {
            let mode = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();
            let mut conn = db::open_for_write(&fx.db_path).unwrap();
            db::insert_row_with_key(
                &mut conn,
                &db::test_support::sample_entry(),
                &mode.hash_key(),
            )
            .unwrap();
        }

        let mode = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();
        assert!(matches!(mode, ChainMode::Hmac { .. }));
    }

    /// Deleting a cadence row must not pass the metadata HMAC. It used to:
    /// verification recomputed over `unwrap_or(30)`/`unwrap_or(90)`, which
    /// on a default install reproduces the genesis MAC exactly, after which
    /// `verify` fell back to the config file's cadence -- the retroactive
    /// widening the genesis-fixed cadence exists to prevent.
    #[test]
    fn deleting_a_cadence_row_is_caught_by_the_metadata_hmac() {
        for key in ["heartbeat_cadence_max_secs", "heartbeat_cadence_min_secs"] {
            let fx = Fixture::new(&format!("cadence_del_{key}"));
            bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();

            {
                let conn = db::open_for_write(&fx.db_path).unwrap();
                conn.execute("DELETE FROM chain_metadata WHERE key = ?1", [key])
                    .unwrap();
            }

            let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
            assert!(
                err.to_string().contains("chain_metadata"),
                "deleting {key} must be refused, got: {err}"
            );
            remove_db_files(&fx.db_path);
        }
    }

    /// Same lever, using a value the parser rejects rather than a deletion:
    /// `read_chain_metadata` maps an unparseable cadence to `None`, which
    /// defaulted the same way.
    #[test]
    fn an_unparseable_cadence_row_is_caught_by_the_metadata_hmac() {
        let fx = Fixture::new("cadence_garbage");
        bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();

        {
            let conn = db::open_for_write(&fx.db_path).unwrap();
            conn.execute(
                "UPDATE chain_metadata SET value = 'x' WHERE key = 'heartbeat_cadence_max_secs'",
                [],
            )
            .unwrap();
        }

        let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
        assert!(err.to_string().contains("chain_metadata"), "{err}");
        remove_db_files(&fx.db_path);
    }

    #[test]
    fn existing_hmac_db_with_missing_key_refuses_to_start() {
        let fx = Fixture::new("missing_key");
        {
            let mode = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();
            let mut conn = db::open_for_write(&fx.db_path).unwrap();
            db::insert_row_with_key(
                &mut conn,
                &db::test_support::sample_entry(),
                &mode.hash_key(),
            )
            .unwrap();
        }
        std::fs::remove_file(&fx.key_path).unwrap();

        let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
        assert!(err.to_string().contains("chain key is"), "{err}");
    }

    /// Regression test for fix #1: `chain_metadata` is a plain table with
    /// no hash-chain linkage of its own, so editing it directly (without
    /// touching any `tool_calls` row) must still be caught -- otherwise an
    /// attacker with DB write access could e.g. widen
    /// `heartbeat_cadence_max_secs` to suppress gap detection while
    /// `verify` and `run` both kept reporting a clean, HMAC-protected
    /// chain.
    #[test]
    fn tampered_chain_metadata_refuses_to_start_even_though_tool_calls_is_untouched() {
        let fx = Fixture::new("tampered_metadata");
        {
            let mode = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();
            let mut conn = db::open_for_write(&fx.db_path).unwrap();
            db::insert_row_with_key(
                &mut conn,
                &db::test_support::sample_entry(),
                &mode.hash_key(),
            )
            .unwrap();
        }

        // Directly edit chain_metadata, bypassing the hash chain entirely
        // -- no tool_calls row is touched.
        {
            let conn = db::open_for_write(&fx.db_path).unwrap();
            conn.execute(
                "UPDATE chain_metadata SET value = '999999' WHERE key = 'heartbeat_cadence_max_secs'",
                [],
            )
            .unwrap();
        }

        let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
        assert!(
            err.to_string()
                .contains("chain_metadata failed HMAC verification"),
            "{err}"
        );
    }

    #[test]
    fn existing_hmac_db_with_wrong_key_refuses_to_start() {
        let fx = Fixture::new("wrong_key");
        {
            let mode = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();
            let mut conn = db::open_for_write(&fx.db_path).unwrap();
            db::insert_row_with_key(
                &mut conn,
                &db::test_support::sample_entry(),
                &mode.hash_key(),
            )
            .unwrap();
        }
        // Swap in a different key file with the same db_uuid but a
        // different root key.
        let bogus = crate::keys::KeyFile::generate("irrelevant");
        bogus.save(&fx.key_path).unwrap();

        let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
        assert!(err.to_string().contains("HMAC verification"), "{err}");
    }

    /// A database with rows but no `chain_metadata` row at all: either a
    /// pre-Phase-3.5 database, or an HMAC chain whose metadata was deleted.
    /// The two are indistinguishable from here, so both are refused rather
    /// than silently continuing unkeyed.
    #[test]
    fn a_database_with_rows_and_no_metadata_refuses_to_start() {
        let fx = Fixture::new("legacy");
        {
            let mut conn = db::open_for_write(&fx.db_path).unwrap();
            db::insert_row(&mut conn, &db::test_support::sample_entry()).unwrap();
        }
        assert!(!fx.key_path.exists());

        let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
        assert!(
            err.to_string().contains("no usable chain_metadata"),
            "{err}"
        );
        assert!(
            !fx.key_path.exists(),
            "refusing to start must not generate a key file"
        );
        remove_db_files(&fx.db_path);
    }

    /// The downgrade lever this strictness exists to close: an HMAC chain
    /// whose single `hmac_version` row is deleted used to fall through to
    /// `ChainMode::Legacy` and append unkeyed rows, because the
    /// metadata-HMAC guard only runs inside the `hmac_version == "1"` arm.
    #[test]
    fn deleting_hmac_version_does_not_downgrade_to_legacy() {
        let fx = Fixture::new("drop_hmac_version");
        bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap();

        {
            let conn = db::open_for_write(&fx.db_path).unwrap();
            conn.execute("DELETE FROM chain_metadata WHERE key = 'hmac_version'", [])
                .unwrap();
        }

        let err = bootstrap(&fx.db_path, &fx.key_path, 30, 90).unwrap_err();
        assert!(
            err.to_string().contains("no usable chain_metadata"),
            "{err}"
        );
        remove_db_files(&fx.db_path);
    }
}
