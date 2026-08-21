//! The derived `redactions` index: fail-open projection at insert time, the
//! `redaction_flags`-vs-index consistency check `verify` runs, and
//! `--repair-index`'s plan/apply.
//!
//! Split out of `db.rs` because this is a distinct concern from schema/
//! connection management, the hash chain itself, and the writer thread --
//! each has its own file in this directory (see `db/mod.rs`).

use rusqlite::{params, Connection};
use std::collections::HashMap;

/// One entry of the `[{"pattern":..,"severity":..,"sha256":..}]` shape
/// `proxy.rs` writes into `redaction_flags` (see its `RedactionRecord`).
#[derive(serde::Deserialize)]
pub(crate) struct RedactionEntry {
    pattern: String,
    severity: String,
    sha256: String,
}

pub(crate) const INSERT_REDACTION_SQL: &str = r#"
INSERT INTO redactions (tool_call_id, pattern, severity, secret_sha256) VALUES (?1, ?2, ?3, ?4)
"#;

/// Fail-open projection into the `redactions` index: any failure here is
/// warned about loudly (stderr, like every other fail-open path) but never
/// propagated, so the primary `tool_calls` row still commits. The warning
/// names the consequence explicitly — index drift, i.e. `unmask` may not
/// resolve this row's hashes — and points at `verify`, which detects drift
/// after the fact (see `check_redaction_consistency`).
pub(crate) fn insert_redaction_rows(conn: &Connection, flags_json: &str) {
    let records: Vec<RedactionEntry> = match serde_json::from_str(flags_json) {
        Ok(records) => records,
        Err(e) => {
            tracing::warn!(
                "redactions index drift: failed to parse redaction_flags for the indexed projection \
                 (the audit row itself is committed and intact, but `unmask` will not resolve this row's \
                 secret hashes; run `auditmcp verify` to see all drifted rows): {e}"
            );
            return;
        }
    };

    let tool_call_id = conn.last_insert_rowid();
    for r in records {
        if let Err(e) = conn.execute(
            INSERT_REDACTION_SQL,
            params![tool_call_id, r.pattern, r.severity, r.sha256],
        ) {
            tracing::warn!(
                "redactions index drift: failed to insert index row for tool_call {tool_call_id} \
                 (the audit row itself is committed and intact, but `unmask` will not resolve this hash; \
                 run `auditmcp verify` to see all drifted rows): {e}"
            );
        }
    }
}

/// One detected mismatch between `tool_calls.redaction_flags` (the source
/// of truth) and the derived `redactions` index for a single tool call.
#[derive(Debug)]
pub struct RedactionDrift {
    pub tool_call_id: i64,
    pub detail: String,
}

/// Compares every row's `redaction_flags` JSON against what's actually in
/// the `redactions` index and reports each mismatch. The index is populated
/// fail-open (see `insert_redaction_rows`), so drift is possible by design
/// — a drifted row's audit record is intact, but `unmask` won't resolve its
/// hashes until the drift is addressed. Read-only; used by `verify`.
///
/// Cost profile matches `verify`'s existing full-table chain walk (this is
/// an offline integrity command, not hot-path code), unlike `unmask`'s
/// resolution, which stays on the indexed lookups above.
pub fn check_redaction_consistency(conn: &Connection) -> anyhow::Result<Vec<RedactionDrift>> {
    let mut state = load_redaction_state(conn)?;
    let mut drift = std::mem::take(&mut state.unparseable);

    for id in state.all_ids() {
        let exp = state
            .expected
            .get(&id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let act = state.actual.get(&id).map(Vec::as_slice).unwrap_or_default();
        let (missing, extra) = diff_triples(exp, act);

        if !missing.is_empty() || !extra.is_empty() {
            let mut parts = Vec::new();
            if !missing.is_empty() {
                parts.push(format!(
                    "missing from index: {}",
                    missing
                        .iter()
                        .map(short_triple)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !extra.is_empty() {
                parts.push(format!(
                    "in index but not in redaction_flags: {}",
                    extra
                        .iter()
                        .map(short_triple)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            drift.push(RedactionDrift {
                tool_call_id: id,
                detail: parts.join("; "),
            });
        }
    }

    drift.sort_by_key(|d| d.tool_call_id);
    Ok(drift)
}

/// A (pattern, severity, sha256) triple — one redaction hit, as recorded in
/// both `redaction_flags` (the source of truth) and the `redactions` index.
pub type RedactionTriple = (String, String, String);

/// Both sides of the source-of-truth vs. index comparison, loaded once and
/// shared by `check_redaction_consistency` and the repair planner so they
/// can never disagree about what "consistent" means.
struct RedactionState {
    /// Triples each tool_call SHOULD have in the index, per its
    /// `redaction_flags` JSON.
    expected: HashMap<i64, Vec<RedactionTriple>>,
    /// Triples actually present in the `redactions` index.
    actual: HashMap<i64, Vec<RedactionTriple>>,
    /// Rows whose `redaction_flags` isn't parseable JSON: the index can't
    /// be verified against them, and `--repair-index` has no source of
    /// truth to rebuild them from.
    unparseable: Vec<RedactionDrift>,
}

impl RedactionState {
    /// Every tool_call id present on either side, sorted, deduplicated.
    fn all_ids(&self) -> Vec<i64> {
        let mut ids: Vec<i64> = self
            .expected
            .keys()
            .chain(self.actual.keys())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

fn load_redaction_state(conn: &Connection) -> anyhow::Result<RedactionState> {
    let mut expected: HashMap<i64, Vec<RedactionTriple>> = HashMap::new();
    let mut unparseable: Vec<RedactionDrift> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT id, redaction_flags FROM tool_calls WHERE redaction_flags IS NOT NULL")
            .map_err(|e| anyhow::anyhow!("failed to prepare redaction_flags scan: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| anyhow::anyhow!("failed to scan redaction_flags: {e}"))?;
        for r in rows {
            let (id, raw) =
                r.map_err(|e| anyhow::anyhow!("failed to read redaction_flags row: {e}"))?;
            match serde_json::from_str::<Vec<RedactionEntry>>(&raw) {
                Ok(records) => {
                    expected.insert(
                        id,
                        records
                            .into_iter()
                            .map(|e| (e.pattern, e.severity, e.sha256))
                            .collect(),
                    );
                }
                // Unparseable source JSON is itself reportable drift: the
                // index can't be verified against it, and the write path
                // couldn't have projected it either.
                Err(e) => unparseable.push(RedactionDrift {
                    tool_call_id: id,
                    detail: format!(
                        "redaction_flags is not parseable JSON ({e}); index cannot be verified"
                    ),
                }),
            }
        }
    }

    let mut actual: HashMap<i64, Vec<RedactionTriple>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT tool_call_id, pattern, severity, secret_sha256 FROM redactions")
            .map_err(|e| anyhow::anyhow!("failed to prepare redactions scan: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    (
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ),
                ))
            })
            .map_err(|e| anyhow::anyhow!("failed to scan redactions: {e}"))?;
        for r in rows {
            let (id, triple) =
                r.map_err(|e| anyhow::anyhow!("failed to read redactions row: {e}"))?;
            actual.entry(id).or_default().push(triple);
        }
    }

    Ok(RedactionState {
        expected,
        actual,
        unparseable,
    })
}

/// Multiset difference for one tool call: `.0` is what's missing from the
/// index, `.1` what's extra in it. Multiset (not set) on purpose: the same
/// secret can legitimately produce two identical triples in one call —
/// duplicated within args, or appearing in both args and result — so
/// duplicates are counted, never deduplicated away (2 expected vs. 2 found
/// is consistent; 2 expected vs. 1 found is drift).
fn diff_triples(
    expected: &[RedactionTriple],
    actual: &[RedactionTriple],
) -> (Vec<RedactionTriple>, Vec<RedactionTriple>) {
    let mut remaining = actual.to_vec();
    let mut missing = Vec::new();
    for e in expected {
        if let Some(pos) = remaining.iter().position(|a| a == e) {
            remaining.remove(pos);
        } else {
            missing.push(e.clone());
        }
    }
    (missing, remaining)
}

fn short_triple(t: &RedactionTriple) -> String {
    format!("{}({}…)", t.0, &t.2[..t.2.len().min(12)])
}

/// What `verify --repair-index` would do (dry run) or did (apply) for one
/// drifted tool call: insert each `add` triple into the `redactions` index
/// and delete one index row per `remove` triple. Derived purely from
/// `redaction_flags`, so applying it makes the index match the source of
/// truth exactly; index rows that already agree are never touched.
pub struct RepairAction {
    pub tool_call_id: i64,
    pub add: Vec<RedactionTriple>,
    pub remove: Vec<RedactionTriple>,
}

pub struct RepairPlan {
    pub actions: Vec<RepairAction>,
    /// Drifted rows repair cannot fix: their `redaction_flags` doesn't
    /// parse, so there's nothing to rebuild the index from. Their existing
    /// index rows (if any) are left untouched rather than guessed at, and
    /// they remain visible as drift afterwards.
    pub unrepairable: Vec<RedactionDrift>,
}

/// Read-only: computes what `--repair-index` would change, without writing.
/// Shares `load_redaction_state`/`diff_triples` with
/// `check_redaction_consistency`, so a repair fixes exactly what the check
/// reports — nothing more.
pub fn plan_redaction_repair(conn: &Connection) -> anyhow::Result<RepairPlan> {
    let state = load_redaction_state(conn)?;
    let mut actions = Vec::new();

    for id in state.all_ids() {
        let exp = state
            .expected
            .get(&id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let act = state.actual.get(&id).map(Vec::as_slice).unwrap_or_default();
        let (missing, extra) = diff_triples(exp, act);
        if !missing.is_empty() || !extra.is_empty() {
            actions.push(RepairAction {
                tool_call_id: id,
                add: missing,
                remove: extra,
            });
        }
    }

    Ok(RepairPlan {
        actions,
        unrepairable: state.unparseable,
    })
}

/// Applies the repair plan in ONE transaction, touching ONLY the derived
/// `redactions` table — never `tool_calls`, and therefore never any
/// `hash`/`prev_hash`: the chain is structurally unaffected (and a test
/// proves the stored hashes are byte-identical across a repair). Unlike the
/// hot-path projection this is NOT fail-open: it's an explicit offline
/// command, so any failure rolls the whole repair back and surfaces to the
/// user instead of being warned past.
pub fn apply_redaction_repair(conn: &Connection) -> anyhow::Result<RepairPlan> {
    let plan = plan_redaction_repair(conn)?;
    if plan.actions.is_empty() {
        return Ok(plan);
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| anyhow::anyhow!("failed to begin repair transaction: {e}"))?;

    for action in &plan.actions {
        for t in &action.remove {
            // Deletes exactly ONE matching index row per extra triple: the
            // diff is a multiset, so two identical extras mean two deletes,
            // and a plain `DELETE .. WHERE tool_call_id/pattern/..` would
            // over-delete legitimate duplicates.
            tx.execute(
                "DELETE FROM redactions WHERE id = (
                   SELECT id FROM redactions
                   WHERE tool_call_id = ?1 AND pattern = ?2 AND severity = ?3 AND secret_sha256 = ?4
                   LIMIT 1)",
                params![action.tool_call_id, t.0, t.1, t.2],
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to delete stray index row for tool_call {}: {e}",
                    action.tool_call_id
                )
            })?;
        }
        for t in &action.add {
            tx.execute(
                INSERT_REDACTION_SQL,
                params![action.tool_call_id, t.0, t.1, t.2],
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to insert index row for tool_call {}: {e}",
                    action.tool_call_id
                )
            })?;
        }
    }

    tx.commit()
        .map_err(|e| anyhow::anyhow!("failed to commit repair transaction: {e}"))?;

    Ok(plan)
}
