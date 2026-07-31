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

/// Hash-chain tamper (or the chain check itself failing). Kept distinct
/// from drift so exit codes alone distinguish the two.
const EXIT_TAMPERED: i32 = 1;
/// Redactions-index drift with an intact chain.
const EXIT_DRIFT: i32 = 2;

pub fn run(config_path: &Path, repair_index: bool, yes: bool) -> anyhow::Result<()> {
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
            // Nonzero exit so this is scriptable (CI, cron, etc.) without
            // the caller having to parse stdout to know the chain broke.
            std::process::exit(EXIT_TAMPERED);
        }
    }

    let drift = db::check_redaction_consistency(&conn)?;
    if drift.is_empty() {
        println!("OK: redactions index consistent with redaction_flags.");
        if repair_index {
            println!("Nothing to repair.");
        }
        return Ok(());
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
        std::process::exit(EXIT_DRIFT);
    }

    if !yes {
        let plan = db::plan_redaction_repair(&conn)?;
        println!("Repair plan (dry run — only the derived redactions index would change, never tool_calls/hashes):");
        print_plan(&plan, "would add", "would remove");
        println!("Dry run: no changes were made. Re-run with `verify --repair-index --yes` to apply.");
        std::process::exit(EXIT_DRIFT);
    }

    let plan = db::apply_redaction_repair(&conn)?;
    println!("Repair applied (only the derived redactions index changed; tool_calls/hashes untouched):");
    print_plan(&plan, "added", "removed");

    // Re-check from the database, not from what we think we just did, and
    // say so — the whole point of the repair is a provably consistent index.
    let remaining = db::check_redaction_consistency(&conn)?;
    if remaining.is_empty() {
        println!("OK: re-checked after repair — redactions index now consistent with redaction_flags.");
        Ok(())
    } else {
        eprintln!(
            "DRIFT: {} row(s) still inconsistent after repair (no parseable redaction_flags to rebuild from):",
            remaining.len()
        );
        for d in &remaining {
            eprintln!("  tool_call id {}: {}", d.tool_call_id, d.detail);
        }
        std::process::exit(EXIT_DRIFT);
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
        println!("  tool_call id {}: cannot repair — {}", u.tool_call_id, u.detail);
    }
}
