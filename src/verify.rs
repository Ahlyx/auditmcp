//! `auditmcp verify` — walk the hash chain from the beginning and confirm
//! no row was altered or removed; report the first broken link if any.
//! Also checks that the derived `redactions` index is consistent with the
//! source-of-truth `redaction_flags` JSON, since that index is populated
//! fail-open and can drift (breaking `unmask` hash resolution) without any
//! tampering having occurred.
//!
//! Phase 3.5 extends this with three more checks, run in this order once
//! the chain itself verifies: heartbeat gaps within a session (rows
//! deleted from the tail, even if the remaining ones still hash-chain
//! cleanly), the anchor's own internal HMAC chain, and the anchor's
//! cross-reference against the database. See the exit code table below.
//!
//! Exit codes are distinct so a monitoring script can tell these apart
//! without parsing output:
//!   0 — chain intact, redactions index consistent, all enabled checks passed
//!   1 — hash-chain / HMAC verification failed (row altered, deleted, or reordered)
//!   2 — chain intact, but EITHER the redactions index drifted from
//!       redaction_flags (repairable via `--repair-index`), OR this is an
//!       HMAC-protected chain and the chain key is missing/unloadable/unknown
//!   3 — a heartbeat gap within a session exceeded the expected cadence
//!   4 — the anchor file's own internal HMAC chain is broken
//!   5 — the anchor references chain rows that are missing or have a
//!       different hash than what the anchor recorded
//!
//! `--repair-index` rebuilds drifted index rows from `redaction_flags` (the
//! source of truth). It only ever adds/removes rows in the derived
//! `redactions` table — never `tool_calls`, `hash`, or `prev_hash` — and is
//! a dry run unless `--yes` is also given.

use crate::config::Config;
use crate::db::{self, HashKey};
use std::path::Path;

/// What `verify` concluded. Returned rather than turned into a
/// `std::process::exit` here so the exit-code policy is testable in-process:
/// `main` is the only place that ends the process, and these variants are
/// the whole contract. A bare `Result<()>` could not express "finished
/// normally, but the answer is nonzero."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Chain intact AND redactions index consistent AND every enabled
    /// Phase 3.5 check passed.
    Clean,
    /// Hash-chain verification failed: a row was altered, deleted, or
    /// reordered. Kept distinct from drift so exit codes alone tell
    /// "someone tampered with the audit log" from "an index went stale."
    Tampered,
    /// Chain intact, but either the derived redactions index drifted from
    /// `redaction_flags`, or (Phase 3.5) this database is HMAC-protected
    /// and the chain key could not be loaded or is for an unknown
    /// `hmac_version`. Also returned for a `--repair-index` dry run and
    /// for drift that remained unrepairable, since in neither case is the
    /// index consistent when the command ends.
    Drift,
    /// A gap between two consecutive `__heartbeat` rows in the same
    /// session exceeded `heartbeat_cadence_max_secs * 1.5`.
    HeartbeatGap,
    /// The anchor file's own internal HMAC chain does not verify.
    AnchorChainBroken,
    /// An anchor entry references a chain row that no longer exists, or
    /// exists with a different `hash` than the anchor recorded.
    AnchorMismatch,
}

impl VerifyOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            VerifyOutcome::Clean => 0,
            VerifyOutcome::Tampered => 1,
            VerifyOutcome::Drift => 2,
            VerifyOutcome::HeartbeatGap => 3,
            VerifyOutcome::AnchorChainBroken => 4,
            VerifyOutcome::AnchorMismatch => 5,
        }
    }
}

pub fn run(config_path: &Path, repair_index: bool, yes: bool) -> anyhow::Result<VerifyOutcome> {
    if yes && !repair_index {
        return Err(anyhow::anyhow!("--yes only applies to --repair-index"));
    }

    let config = Config::load(config_path)?;
    let db_path = Path::new(&config.logging.db_path);
    // A writable connection only when actually applying a repair; plain
    // verify AND `--repair-index` dry runs stay strictly read-only.
    let conn = if repair_index && yes {
        db::open_for_write(db_path)?
    } else {
        db::open_readonly(db_path)?
    };

    // Phase 3.5: resolve which hashing scheme this database uses, and for
    // an HMAC chain, load the key needed to check it at all. This mirrors
    // (deliberately) the same decision `chain::bootstrap` makes for `run`
    // -- see that module's doc for why the decision must never be made two
    // different ways.
    let metadata = db::read_chain_metadata(&conn)?;
    let mut anchor_key: Option<[u8; 32]> = None;
    let mut key_fingerprint: Option<String> = None;
    let hash_key = match &metadata {
        Some(m) if m.hmac_version.as_deref() == Some("1") => {
            let key_path = config.chain.resolved_key_path()?;
            let key = match crate::keys::KeyFile::load(&key_path)? {
                Some(k) => k,
                None => {
                    eprintln!(
                        "FAILED: this database is HMAC-protected (Phase 3.5) but its chain \
                         key is missing at {}.",
                        key_path.display()
                    );
                    return Ok(VerifyOutcome::Drift);
                }
            };
            let (chain_key, ak) = key.derive_subkeys(&m.db_uuid)?;
            anchor_key = Some(ak);
            key_fingerprint = Some(key.fingerprint()?);
            HashKey::Hmac(chain_key)
        }
        Some(m) if m.hmac_version.is_some() => {
            eprintln!(
                "FAILED: chain_metadata declares hmac_version {:?}, which this build of \
                 auditmcp does not know how to verify.",
                m.hmac_version
            );
            return Ok(VerifyOutcome::Drift);
        }
        _ => {
            println!(
                "WARNING: this chain uses legacy unkeyed SHA-256. Run 'auditmcp reset \
                 --keep-old' to migrate to an HMAC-protected chain."
            );
            HashKey::Legacy
        }
    };

    match db::verify_chain_with_key(&conn, &hash_key)? {
        Ok(count) => {
            println!("OK: {count} row(s) verified, hash chain intact.");
        }
        Err(issue) => {
            eprintln!("FAILED: {issue}");
            if repair_index {
                eprintln!("(--repair-index not attempted: refusing to modify a database that failed chain verification)");
            }
            // Returned, not exited: `main` turns this into the nonzero exit
            // code that makes the command scriptable (CI, cron) without the
            // caller having to parse stdout to know the chain broke.
            return Ok(VerifyOutcome::Tampered);
        }
    }

    let drift = db::check_redaction_consistency(&conn)?;
    if drift.is_empty() {
        println!("OK: redactions index consistent with redaction_flags.");
        if repair_index {
            println!("Nothing to repair.");
        }
        return finish_clean(
            &conn,
            &config,
            &metadata,
            anchor_key,
            key_fingerprint.as_deref(),
        );
    }

    // Distinct wording from the chain-tamper FAILED above: drift is not
    // evidence of tampering (the hash-chained audit record just passed
    // verification), but it does mean `unmask` may fail to resolve the
    // affected hashes, so it still exits nonzero — with its own code (2,
    // vs 1 for tamper) for scriptability.
    eprintln!(
        "DRIFT: hash chain is intact, but the redactions index is out of sync with redaction_flags on {} row(s):",
        drift.len()
    );
    for d in &drift {
        eprintln!("  tool_call id {}: {}", d.tool_call_id, d.detail);
    }
    eprintln!("(`unmask` may not resolve hashes on the affected rows; the audit records themselves are unaffected)");

    if !repair_index {
        return Ok(VerifyOutcome::Drift);
    }

    if !yes {
        let plan = db::plan_redaction_repair(&conn)?;
        println!("Repair plan (dry run — only the derived redactions index would change, never tool_calls/hashes):");
        print_plan(&plan, "would add", "would remove");
        println!(
            "Dry run: no changes were made. Re-run with `verify --repair-index --yes` to apply."
        );
        return Ok(VerifyOutcome::Drift);
    }

    let plan = db::apply_redaction_repair(&conn)?;
    println!(
        "Repair applied (only the derived redactions index changed; tool_calls/hashes untouched):"
    );
    print_plan(&plan, "added", "removed");

    // Re-check from the database, not from what we think we just did, and
    // say so — the whole point of the repair is a provably consistent index.
    let remaining = db::check_redaction_consistency(&conn)?;
    if remaining.is_empty() {
        println!(
            "OK: re-checked after repair — redactions index now consistent with redaction_flags."
        );
        finish_clean(
            &conn,
            &config,
            &metadata,
            anchor_key,
            key_fingerprint.as_deref(),
        )
    } else {
        eprintln!(
            "DRIFT: {} row(s) still inconsistent after repair (no parseable redaction_flags to rebuild from):",
            remaining.len()
        );
        for d in &remaining {
            eprintln!("  tool_call id {}: {}", d.tool_call_id, d.detail);
        }
        Ok(VerifyOutcome::Drift)
    }
}

/// Runs the three Phase 3.5 checks (heartbeat gaps, anchor internal chain,
/// anchor-vs-database cross-check) and, if all pass, prints the closing
/// summary report and returns `Clean`. Called from every place `run` is
/// about to conclude the chain/redactions checks are clean -- factored out
/// so those checks can't be skipped from one return path and not another.
fn finish_clean(
    conn: &rusqlite::Connection,
    config: &Config,
    metadata: &Option<db::ChainMetadata>,
    anchor_key: Option<[u8; 32]>,
    key_fingerprint: Option<&str>,
) -> anyhow::Result<VerifyOutcome> {
    let rows = db::read_all_rows(conn)?;

    if config.heartbeat.enabled {
        let cadence_max = metadata
            .as_ref()
            .and_then(|m| m.heartbeat_cadence_max_secs)
            .unwrap_or(config.heartbeat.cadence_max_secs);
        let gaps = crate::heartbeat::find_heartbeat_gaps(&rows, cadence_max);
        if !gaps.is_empty() {
            eprintln!(
                "FAILED: {} heartbeat gap(s) exceeded the expected cadence (max allowed {}s):",
                gaps.len(),
                (cadence_max as f64 * 1.5) as i64
            );
            for g in &gaps {
                eprintln!(
                    "  session {}: {}s gap between {} and {}",
                    g.session_id, g.gap_secs, g.after_timestamp, g.before_timestamp
                );
            }
            return Ok(VerifyOutcome::HeartbeatGap);
        }
    }

    if config.anchor.enabled {
        if let Some(anchor_key) = anchor_key {
            let anchor_path = crate::anchor::resolve_anchor_path(&config.anchor.path)?;
            let entries = crate::anchor::read_entries(&anchor_path)?;
            if entries.is_empty() {
                println!(
                    "Anchor: no entries found at {} (never written this session, or the file \
                     hasn't been created yet).",
                    anchor_path.display()
                );
            } else {
                if let Some(issue) = crate::anchor::verify_anchor_chain(&entries, &anchor_key) {
                    eprintln!("FAILED: {issue}");
                    return Ok(VerifyOutcome::AnchorChainBroken);
                }
                let mismatches = crate::anchor::verify_anchor_against_chain(&entries, &rows);
                if !mismatches.is_empty() {
                    eprintln!(
                        "FAILED: anchor cross-check against the database found {} issue(s):",
                        mismatches.len()
                    );
                    for m in &mismatches {
                        eprintln!("  {m}");
                    }
                    return Ok(VerifyOutcome::AnchorMismatch);
                }
                println!(
                    "OK: anchor chain intact and consistent with the database ({} entries, last at {}).",
                    entries.len(),
                    entries.last().map(|e| e.timestamp.as_str()).unwrap_or("-")
                );
            }
        }
    }

    let session_count = rows
        .iter()
        .map(|r| r.entry.session_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    println!(
        "Summary: {} row(s), {} session(s), last row at {}{}{}",
        rows.len(),
        session_count,
        rows.last()
            .map(|r| r.entry.timestamp.as_str())
            .unwrap_or("-"),
        key_fingerprint
            .map(|fp| format!(", key fingerprint {fp}"))
            .unwrap_or_default(),
        metadata
            .as_ref()
            .and_then(|m| m.created_at.as_deref())
            .map(|c| format!(", chain created at {c}"))
            .unwrap_or_default(),
    );

    Ok(VerifyOutcome::Clean)
}

fn print_plan(plan: &db::RepairPlan, add_verb: &str, remove_verb: &str) {
    for a in &plan.actions {
        println!(
            "  tool_call id {}: {add_verb} {} index row(s), {remove_verb} {}",
            a.tool_call_id,
            a.add.len(),
            a.remove.len()
        );
    }
    for u in &plan.unrepairable {
        println!(
            "  tool_call id {}: cannot repair — {}",
            u.tool_call_id, u.detail
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::{remove_db_files, seed_chain, seed_redacted_row, temp_db_path};

    const SHA: &str = "1a87c48fe71852d0a7d47d36fba37625aecb7d4df1c9753fcbcb57f3a66e5598";

    /// A temp DB plus a config file pointing at it. `verify::run` takes a
    /// config path (not a `Connection`), so exercising its real entry point
    /// means writing a real config — which also covers the config plumbing.
    struct Fixture {
        db_path: std::path::PathBuf,
        config_path: std::path::PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let db_path = temp_db_path(label);
            let config_path = db_path.with_extension("toml");
            // `[target]` is required by the current schema even though
            // `verify` never reads it, so a valid config must include it.
            // db_path is absolute and may contain backslashes on Windows,
            // so it goes in as a TOML literal string (single quotes), which
            // has no escape processing.
            std::fs::write(
                &config_path,
                format!(
                    "[target]\n[logging]\ndb_path = '{}'\n",
                    db_path.to_string_lossy()
                ),
            )
            .unwrap();
            Fixture {
                db_path,
                config_path,
            }
        }

        fn open(&self) -> rusqlite::Connection {
            db::open_for_write(&self.db_path).unwrap()
        }

        fn run(&self, repair_index: bool, yes: bool) -> anyhow::Result<VerifyOutcome> {
            super::run(&self.config_path, repair_index, yes)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            remove_db_files(&self.db_path);
            let _ = std::fs::remove_file(&self.config_path);
        }
    }

    #[test]
    fn exit_codes_match_the_documented_contract() {
        assert_eq!(VerifyOutcome::Clean.exit_code(), 0);
        assert_eq!(VerifyOutcome::Tampered.exit_code(), 1);
        assert_eq!(VerifyOutcome::Drift.exit_code(), 2);
    }

    #[test]
    fn yes_without_repair_index_is_rejected() {
        let fx = Fixture::new("verify_yes_alone");
        let err = fx.run(false, true).unwrap_err();
        assert!(err.to_string().contains("--yes only applies"));
    }

    #[test]
    fn intact_chain_is_clean() {
        let fx = Fixture::new("verify_clean");
        let mut conn = fx.open();
        seed_chain(&mut conn, 3);
        drop(conn);

        assert_eq!(fx.run(false, false).unwrap(), VerifyOutcome::Clean);
    }

    #[test]
    fn an_empty_database_is_clean() {
        let fx = Fixture::new("verify_empty");
        drop(fx.open());
        assert_eq!(fx.run(false, false).unwrap(), VerifyOutcome::Clean);
    }

    #[test]
    fn altered_row_reports_tampered() {
        let fx = Fixture::new("verify_tampered");
        let mut conn = fx.open();
        seed_chain(&mut conn, 3);
        conn.execute("UPDATE tool_calls SET tool_name='innocuous' WHERE id=2", [])
            .unwrap();
        drop(conn);

        assert_eq!(fx.run(false, false).unwrap(), VerifyOutcome::Tampered);
    }

    #[test]
    fn deleted_middle_row_reports_tampered() {
        let fx = Fixture::new("verify_deleted");
        let mut conn = fx.open();
        seed_chain(&mut conn, 3);
        conn.execute("DELETE FROM tool_calls WHERE id=2", [])
            .unwrap();
        drop(conn);

        assert_eq!(fx.run(false, false).unwrap(), VerifyOutcome::Tampered);
    }

    /// Drift is the derived index disagreeing with `redaction_flags`, the
    /// source of truth — not tampering. The chain still verifies.
    #[test]
    fn index_drift_reports_drift_not_tampered() {
        let fx = Fixture::new("verify_drift");
        let mut conn = fx.open();
        let id = seed_redacted_row(&mut conn, SHA);
        conn.execute("DELETE FROM redactions WHERE tool_call_id=?1", [id])
            .unwrap();
        drop(conn);

        assert_eq!(fx.run(false, false).unwrap(), VerifyOutcome::Drift);
    }

    /// A dry run must report drift (the index is still inconsistent when
    /// the command ends) and must not write anything.
    #[test]
    fn repair_dry_run_reports_drift_and_changes_nothing() {
        let fx = Fixture::new("verify_dry");
        let mut conn = fx.open();
        let id = seed_redacted_row(&mut conn, SHA);
        conn.execute("DELETE FROM redactions WHERE tool_call_id=?1", [id])
            .unwrap();
        drop(conn);

        assert_eq!(fx.run(true, false).unwrap(), VerifyOutcome::Drift);

        let conn = fx.open();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM redactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "dry run must not repair the index");
    }

    #[test]
    fn repair_with_yes_rebuilds_the_index_and_returns_clean() {
        let fx = Fixture::new("verify_repair");
        let mut conn = fx.open();
        let id = seed_redacted_row(&mut conn, SHA);
        conn.execute("DELETE FROM redactions WHERE tool_call_id=?1", [id])
            .unwrap();
        drop(conn);

        assert_eq!(fx.run(true, true).unwrap(), VerifyOutcome::Clean);

        let conn = fx.open();
        let stored: String = conn
            .query_row(
                "SELECT secret_sha256 FROM redactions WHERE tool_call_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, SHA, "index must be rebuilt from redaction_flags");
    }

    /// Repair must never run against a database that failed chain
    /// verification: writing to a log that may have been tampered with is
    /// exactly the wrong response, and the tamper result must win over the
    /// drift that may also be present.
    #[test]
    fn repair_refuses_when_the_chain_is_tampered() {
        let fx = Fixture::new("verify_tampered_repair");
        let mut conn = fx.open();
        let id = seed_redacted_row(&mut conn, SHA);
        conn.execute("DELETE FROM redactions WHERE tool_call_id=?1", [id])
            .unwrap();
        conn.execute(
            "UPDATE tool_calls SET tool_name='innocuous' WHERE id=?1",
            [id],
        )
        .unwrap();
        drop(conn);

        assert_eq!(fx.run(true, true).unwrap(), VerifyOutcome::Tampered);

        let conn = fx.open();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM redactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 0,
            "a tampered database must not be written to, even to repair a derived index"
        );
    }

    // ---- Phase 3.5: HMAC / heartbeat / anchor -----------------------

    /// A config + key/anchor paths for exercising the Phase 3.5 checks.
    /// `heartbeat_max_secs`/`anchor_enabled` are baked into the written
    /// config so each test can dial in exactly the cadence/anchor
    /// behavior it needs.
    struct HmacFixture {
        db_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
        anchor_path: std::path::PathBuf,
        config_path: std::path::PathBuf,
    }

    impl HmacFixture {
        fn new(label: &str, heartbeat_max_secs: u64, anchor_enabled: bool) -> Self {
            let db_path = temp_db_path(label);
            let key_path = std::env::temp_dir().join(format!(
                "auditmcp_test_verify_key_{label}_{}.key",
                uuid::Uuid::new_v4()
            ));
            let anchor_path = std::env::temp_dir().join(format!(
                "auditmcp_test_verify_anchor_{label}_{}.log",
                uuid::Uuid::new_v4()
            ));
            let config_path = db_path.with_extension("toml");
            std::fs::write(
                &config_path,
                format!(
                    "[target]\n[logging]\ndb_path = '{}'\n\
                     [chain]\nkey_path = '{}'\n\
                     [heartbeat]\nenabled = true\ncadence_min_secs = 1\ncadence_max_secs = {}\n\
                     [anchor]\nenabled = {}\npath = '{}'\n",
                    db_path.to_string_lossy(),
                    key_path.to_string_lossy(),
                    heartbeat_max_secs,
                    anchor_enabled,
                    anchor_path.to_string_lossy(),
                ),
            )
            .unwrap();
            HmacFixture {
                db_path,
                key_path,
                anchor_path,
                config_path,
            }
        }

        fn bootstrap(&self) -> crate::chain::ChainMode {
            crate::chain::bootstrap(&self.db_path, &self.key_path, 1, 90).unwrap()
        }

        fn run(&self) -> anyhow::Result<VerifyOutcome> {
            super::run(&self.config_path, false, false)
        }
    }

    impl Drop for HmacFixture {
        fn drop(&mut self) {
            remove_db_files(&self.db_path);
            let _ = std::fs::remove_file(&self.key_path);
            let _ = std::fs::remove_file(&self.anchor_path);
            let _ = std::fs::remove_file(&self.config_path);
        }
    }

    fn hmac_row(session_id: &str, tool_name: &str, timestamp: &str) -> db::ToolCallEntry {
        let mut e = db::test_support::sample_entry();
        e.session_id = session_id.to_string();
        e.tool_name = tool_name.to_string();
        e.timestamp = timestamp.to_string();
        e
    }

    #[test]
    fn fresh_hmac_chain_verifies_clean() {
        let fx = HmacFixture::new("hmac_clean", 90, false);
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        db::insert_row_with_key(
            &mut conn,
            &hmac_row("s1", "echo", "2026-01-01T00:00:00Z"),
            &mode.hash_key(),
        )
        .unwrap();
        drop(conn);

        assert_eq!(fx.run().unwrap(), VerifyOutcome::Clean);
    }

    #[test]
    fn hmac_chain_with_missing_key_reports_drift_code() {
        let fx = HmacFixture::new("hmac_missing_key", 90, false);
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        db::insert_row_with_key(
            &mut conn,
            &hmac_row("s1", "echo", "2026-01-01T00:00:00Z"),
            &mode.hash_key(),
        )
        .unwrap();
        drop(conn);
        std::fs::remove_file(&fx.key_path).unwrap();

        assert_eq!(fx.run().unwrap(), VerifyOutcome::Drift);
    }

    /// A too-wide gap between two heartbeats in the same session is
    /// detected even though the chain itself hash-verifies cleanly --
    /// exactly the "tail truncation is invisible to hashing alone" gap
    /// heartbeats exist to close.
    #[test]
    fn wide_heartbeat_gap_returns_heartbeat_gap_outcome() {
        let fx = HmacFixture::new("hmac_hb_gap", 1, false); // max cadence 1s -> 1.5s allowed
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        let mut hb1 = crate::heartbeat::heartbeat_entry("s1", "srv", 1, chrono::Utc::now());
        let mut hb2 = crate::heartbeat::heartbeat_entry("s1", "srv", 2, chrono::Utc::now());
        hb1.timestamp = "2026-01-01T00:00:00Z".to_string();
        hb2.timestamp = "2026-01-01T00:05:00Z".to_string(); // 300s gap, way over 1.5s
        db::insert_row_with_key(&mut conn, &hb1, &mode.hash_key()).unwrap();
        db::insert_row_with_key(&mut conn, &hb2, &mode.hash_key()).unwrap();
        drop(conn);

        assert_eq!(fx.run().unwrap(), VerifyOutcome::HeartbeatGap);
    }

    #[test]
    fn heartbeats_within_cadence_stay_clean() {
        let fx = HmacFixture::new("hmac_hb_ok", 90, false);
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        let mut hb1 = crate::heartbeat::heartbeat_entry("s1", "srv", 1, chrono::Utc::now());
        hb1.timestamp = "2026-01-01T00:00:00Z".to_string();
        let mut hb2 = crate::heartbeat::heartbeat_entry("s1", "srv", 2, chrono::Utc::now());
        hb2.timestamp = "2026-01-01T00:00:30Z".to_string(); // 30s, well under 135s
        db::insert_row_with_key(&mut conn, &hb1, &mode.hash_key()).unwrap();
        db::insert_row_with_key(&mut conn, &hb2, &mode.hash_key()).unwrap();
        drop(conn);

        assert_eq!(fx.run().unwrap(), VerifyOutcome::Clean);
    }

    #[test]
    fn tampered_anchor_entry_returns_anchor_chain_broken() {
        let fx = HmacFixture::new("hmac_anchor_broken", 90, true);
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        let hash = db::insert_row_with_key(
            &mut conn,
            &hmac_row("s1", "echo", "2026-01-01T00:00:00Z"),
            &mode.hash_key(),
        )
        .unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT id FROM tool_calls ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);

        let anchor_key = mode.anchor_key().unwrap();
        crate::anchor::append_entry(&fx.anchor_path, &anchor_key, id, &hash).unwrap();

        // Rewrite the anchor file's one line with a forged chain_last_hash,
        // simulating an attacker who tampered with the anchor itself.
        let content = std::fs::read_to_string(&fx.anchor_path).unwrap();
        let mut entry: crate::anchor::AnchorEntry = serde_json::from_str(content.trim()).unwrap();
        entry.chain_last_hash = "forged".to_string();
        std::fs::write(&fx.anchor_path, serde_json::to_string(&entry).unwrap()).unwrap();

        assert_eq!(fx.run().unwrap(), VerifyOutcome::AnchorChainBroken);
    }

    #[test]
    fn anchor_referencing_a_deleted_row_returns_anchor_mismatch() {
        let fx = HmacFixture::new("hmac_anchor_mismatch", 90, true);
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        let hash = db::insert_row_with_key(
            &mut conn,
            &hmac_row("s1", "echo", "2026-01-01T00:00:00Z"),
            &mode.hash_key(),
        )
        .unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT id FROM tool_calls ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        let anchor_key = mode.anchor_key().unwrap();
        crate::anchor::append_entry(&fx.anchor_path, &anchor_key, id, &hash).unwrap();

        // Delete the row the anchor references -- but leave the chain
        // otherwise walkable by also removing nothing else, so this test
        // isolates the anchor cross-check rather than tripping the earlier
        // hash-chain walk. Deleting the only row makes the chain trivially
        // empty (still verifies as intact -- zero rows), so the anchor
        // mismatch is the only failure this test can hit.
        conn.execute("DELETE FROM tool_calls WHERE id = ?1", [id])
            .unwrap();
        drop(conn);

        assert_eq!(fx.run().unwrap(), VerifyOutcome::AnchorMismatch);
    }

    #[test]
    fn clean_anchor_matching_the_chain_stays_clean() {
        let fx = HmacFixture::new("hmac_anchor_clean", 90, true);
        let mode = fx.bootstrap();
        let mut conn = db::open_for_write(&fx.db_path).unwrap();
        let hash = db::insert_row_with_key(
            &mut conn,
            &hmac_row("s1", "echo", "2026-01-01T00:00:00Z"),
            &mode.hash_key(),
        )
        .unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT id FROM tool_calls ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);

        let anchor_key = mode.anchor_key().unwrap();
        crate::anchor::append_entry(&fx.anchor_path, &anchor_key, id, &hash).unwrap();

        assert_eq!(fx.run().unwrap(), VerifyOutcome::Clean);
    }
}
