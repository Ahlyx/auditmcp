//! `auditmcp verify` — walk the hash chain from the beginning and confirm
//! no row was altered or removed; report the first broken link if any.
//! Also checks that the derived `redactions` index is consistent with the
//! source-of-truth `redaction_flags` JSON, since that index is populated
//! fail-open and can drift (breaking `unmask` hash resolution) without any
//! tampering having occurred.
//!
//! Exit codes are distinct so a monitoring script can tell "someone
//! tampered with the audit log" apart from "an internal index went stale"
//! without parsing output:
//!   0 — chain intact AND redactions index consistent
//!   1 — hash-chain verification failed (row altered, deleted, or reordered)
//!   2 — chain intact, but the redactions index has drifted from
//!       redaction_flags (repairable via `--repair-index`)
//!
//! `--repair-index` rebuilds drifted index rows from `redaction_flags` (the
//! source of truth). It only ever adds/removes rows in the derived
//! `redactions` table — never `tool_calls`, `hash`, or `prev_hash` — and is
//! a dry run unless `--yes` is also given.

use crate::config::Config;
use crate::db;
use std::path::Path;

/// What `verify` concluded. Returned rather than turned into a
/// `std::process::exit` here so the exit-code policy is testable in-process:
/// `main` is the only place that ends the process, and these three variants
/// are the whole contract. A bare `Result<()>` could not express "finished
/// normally, but the answer is nonzero."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Chain intact AND redactions index consistent.
    Clean,
    /// Hash-chain verification failed: a row was altered, deleted, or
    /// reordered. Kept distinct from drift so exit codes alone tell
    /// "someone tampered with the audit log" from "an index went stale."
    Tampered,
    /// Chain intact, but the derived redactions index drifted from
    /// `redaction_flags`. Also returned for a `--repair-index` dry run and
    /// for drift that remained unrepairable, since in neither case is the
    /// index consistent when the command ends.
    Drift,
}

impl VerifyOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            VerifyOutcome::Clean => 0,
            VerifyOutcome::Tampered => 1,
            VerifyOutcome::Drift => 2,
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

    match db::verify_chain(&conn)? {
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
        return Ok(VerifyOutcome::Clean);
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
        Ok(VerifyOutcome::Clean)
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
}
