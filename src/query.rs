//! `auditmcp query` — read logged tool calls back in a readable table.
//!
//! Default output never shows redaction details: `args_json`/`result_json`
//! are already safe to print as-is (secrets are redacted before they're
//! ever written), so the plain table just shows them. `--verbose` adds an
//! opt-in, compact per-row summary of what was redacted and why -- pattern,
//! severity, and whether that hash has since been confirmed a false
//! positive via `unmask`. This command never writes to the database,
//! including under `--verbose`; `unmask` is a separate, deliberate command.

use crate::config::Config;
use crate::db::{self, StoredRow};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::io::{self, BufWriter, Write};
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: &Path,
    tool: Option<String>,
    session: Option<String>,
    since: Option<String>,
    status: Option<String>,
    anomalous: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::open_readonly(Path::new(&config.logging.db_path))?;
    let rows = db::read_all_rows(&conn)?;
    let allowlist = if verbose {
        db::load_allowlist(&conn)?
    } else {
        HashSet::new()
    };

    let since_cutoff = since.as_deref().map(parse_since).transpose()?;
    let filtered = filter_rows(
        rows,
        tool.as_deref(),
        session.as_deref(),
        None,
        since_cutoff,
        status.as_deref(),
        anomalous,
    );

    if filtered.is_empty() {
        println!("No matching tool calls.");
        return Ok(());
    }

    // One locked, buffered writer for the whole table rather than a
    // `println!` per row. Each `println!` takes the stdout lock and flushes
    // its own line, which is unnoticeable for a handful of rows and
    // dominates everything else once the log is large: rendering 200k rows
    // took 83s that way against 8s through a BufWriter, while reading those
    // same rows took under a second. Errors are ignored for the same reason
    // `println!` ignores them -- a closed pipe (`| head`) is a normal way to
    // stop reading, not a failure of the query.
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    // Header literals passed positionally (not inlined) to mirror the data
    // rows below and keep the column format string in one visible place.
    #[allow(clippy::write_literal)]
    let _ = writeln!(
        out,
        "{:<5} {:<30} {:<20} {:<8} {:>9}  {}",
        "ID", "TIMESTAMP", "TOOL", "STATUS", "DUR(ms)", "PREVIEW"
    );
    for row in &filtered {
        let preview = row
            .entry
            .args_json
            .as_deref()
            .map(|s| truncate_display(s, 40))
            .unwrap_or_default();
        let duration = row
            .entry
            .duration_ms
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".to_string());

        let _ = writeln!(
            out,
            "{:<5} {:<30} {:<20} {:<8} {:>9}  {}",
            row.id, row.entry.timestamp, row.entry.tool_name, row.entry.status, duration, preview
        );

        if anomalous {
            if let Some(summary) = anomaly_summary(
                row.entry.anomaly_score,
                row.entry.anomaly_reasons.as_deref(),
            ) {
                let _ = writeln!(out, "      {summary}");
            }
        }
        if verbose {
            if let Some(summary) =
                redaction_summary(row.entry.redaction_flags.as_deref(), &allowlist)
            {
                let _ = writeln!(out, "      {summary}");
            }
        }
    }
    let _ = writeln!(out, "({} row(s))", filtered.len());
    // Explicit, so a write failure surfaces here rather than being
    // swallowed by BufWriter's drop.
    out.flush()
        .map_err(|e| anyhow::anyhow!("failed writing query output: {e}"))?;

    Ok(())
}

/// Filters rows by the criteria `query` and `export` both expose. Shared
/// so the two commands can never quietly diverge on what e.g. `--status
/// error` means. `export` is the only caller that passes `server` (query
/// has no `--server` flag), so it's always `None` from `query::run`.
///
/// `anomalous_only` maps to `WHERE anomaly_score IS NOT NULL`, the shape
/// documented at the anomaly module: rows with no rule fired have both
/// score and reasons columns NULL, so absence and presence are the exact
/// filter contract, not a comparison against zero.
#[allow(clippy::too_many_arguments)]
pub(crate) fn filter_rows(
    rows: Vec<StoredRow>,
    tool: Option<&str>,
    session: Option<&str>,
    server: Option<&str>,
    since_cutoff: Option<DateTime<Utc>>,
    status: Option<&str>,
    anomalous_only: bool,
) -> Vec<StoredRow> {
    rows.into_iter()
        .filter(|r| tool.is_none() || tool == Some(r.entry.tool_name.as_str()))
        .filter(|r| session.is_none() || session == Some(r.entry.session_id.as_str()))
        .filter(|r| server.is_none() || server == r.entry.server_name.as_deref())
        .filter(|r| status.is_none() || status == Some(r.entry.status.as_str()))
        .filter(|r| !anomalous_only || r.entry.anomaly_score.is_some())
        .filter(|r| match since_cutoff {
            None => true,
            Some(cutoff) => match DateTime::parse_from_rfc3339(&r.entry.timestamp) {
                Ok(ts) => ts.with_timezone(&Utc) >= cutoff,
                // Can't parse this row's own timestamp: exclude it rather
                // than guess, since --since is meant to be a hard cutoff.
                Err(_) => false,
            },
        })
        .collect()
}

/// Row shape stored in `redaction_flags` (see `proxy.rs`'s `RedactionRecord`):
/// `[{"pattern":..,"severity":..,"sha256":..}, ...]`. Parsed independently
/// here rather than sharing a type with the proxy/secrets modules, since
/// this is purely a read-side display concern. `pub(crate)` + `Serialize`
/// so `export` can reuse this exact shape rather than re-deriving its own.
#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct StoredRedaction {
    pub pattern: String,
    pub severity: String,
    pub sha256: String,
}

/// Renders `--verbose`'s compact per-row secrets summary, e.g.
/// `[secrets: openai_api_key(high), generic_high_entropy_near_keyword(medium) (now allowlisted)]`.
/// Returns `None` for rows with no redactions (nothing to show) or a
/// `redaction_flags` value that fails to parse (best-effort display,
/// never fatal to the rest of the query).
fn redaction_summary(redaction_flags: Option<&str>, allowlist: &HashSet<String>) -> Option<String> {
    let raw = redaction_flags?;
    let records: Vec<StoredRedaction> = serde_json::from_str(raw).ok()?;
    if records.is_empty() {
        return None;
    }

    // Deliberately forward-looking wording: this row's plaintext was never
    // stored and stays redacted here permanently, regardless of allowlist
    // state -- allowlisting only affects *future* detections of the same
    // secret value. Must not read as "this row got unredacted."
    let parts: Vec<String> = records
        .iter()
        .map(|r| {
            if allowlist.contains(&r.sha256) {
                format!(
                    "{}({}, future occurrences not redacted)",
                    r.pattern, r.severity
                )
            } else {
                format!("{}({})", r.pattern, r.severity)
            }
        })
        .collect();

    Some(format!("[secrets: {}]", parts.join(", ")))
}

/// Row shape stored in `anomaly_reasons`, mirroring
/// `anomaly::Reason`. Deserialized here rather than shared as a type
/// because the anomaly module writes `&'static str` rule names, while
/// the read side must own its strings.
#[derive(serde::Deserialize)]
struct StoredReason {
    rule: String,
    #[allow(dead_code)]
    detail: String,
}

/// Renders `--anomalous`'s per-row summary, e.g.
/// `[anomaly: 2.0 -- size_spike, novel_destination]`. Returns `None` when
/// the score is absent (the row wasn't flagged) or when the reasons
/// column fails to parse -- best-effort display, never fatal to the rest
/// of the query. A score with unparseable reasons still renders the
/// score, since the score alone is a documented column.
fn anomaly_summary(score: Option<f64>, reasons: Option<&str>) -> Option<String> {
    let score = score?;
    let rules: Vec<String> = reasons
        .and_then(|raw| serde_json::from_str::<Vec<StoredReason>>(raw).ok())
        .map(|records| records.into_iter().map(|r| r.rule).collect())
        .unwrap_or_default();
    if rules.is_empty() {
        Some(format!("[anomaly: {score:.1}]"))
    } else {
        Some(format!("[anomaly: {:.1} -- {}]", score, rules.join(", ")))
    }
}

/// Truncates a string to at most `max_chars` characters for display,
/// operating on `char`s (not bytes) so it can never panic by slicing into
/// the middle of a multi-byte UTF-8 sequence.
fn truncate_display(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        return s.replace('\n', " ");
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!("{}...", truncated.replace('\n', " "))
}

/// Parses a `--since` duration like `30m`, `2h`, `1d`, `45s` into an
/// absolute UTC cutoff (now minus that duration). A unit suffix is
/// required — there's no reasonable default unit to guess if one's
/// omitted, and guessing wrong would silently query the wrong window.
pub(crate) fn parse_since(input: &str) -> anyhow::Result<DateTime<Utc>> {
    let input = input.trim();
    let (number_part, unit) = input.split_at(input.len().saturating_sub(1));

    let amount: i64 = number_part.parse().map_err(|_| {
        anyhow::anyhow!("invalid --since value '{input}': expected e.g. 30m, 2h, 1d, 45s")
    })?;

    let duration = match unit {
        "s" => chrono::Duration::seconds(amount),
        "m" => chrono::Duration::minutes(amount),
        "h" => chrono::Duration::hours(amount),
        "d" => chrono::Duration::days(amount),
        other => {
            return Err(anyhow::anyhow!(
                "invalid --since unit '{other}': expected one of s, m, h, d (e.g. 30m, 2h, 1d)"
            ))
        }
    };

    Ok(Utc::now() - duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_display_leaves_short_strings_untouched() {
        assert_eq!(truncate_display("hi", 40), "hi");
    }

    #[test]
    fn truncate_display_does_not_panic_on_multibyte_boundary() {
        let s: String = "✓".repeat(100);
        let out = truncate_display(&s, 40);
        assert!(out.starts_with('✓'));
        assert!(out.ends_with("..."));
    }

    #[test]
    fn parse_since_accepts_valid_units() {
        for unit in ["s", "m", "h", "d"] {
            assert!(parse_since(&format!("5{unit}")).is_ok());
        }
    }

    #[test]
    fn parse_since_rejects_missing_unit() {
        assert!(parse_since("30").is_err());
    }

    #[test]
    fn parse_since_rejects_unknown_unit() {
        assert!(parse_since("30x").is_err());
    }

    #[test]
    fn redaction_summary_is_none_when_no_redactions() {
        assert_eq!(redaction_summary(None, &HashSet::new()), None);
    }

    #[test]
    fn redaction_summary_is_none_on_unparseable_json() {
        assert_eq!(redaction_summary(Some("not json"), &HashSet::new()), None);
    }

    #[test]
    fn redaction_summary_formats_pattern_and_severity() {
        let flags = r#"[{"pattern":"openai_api_key","severity":"high","sha256":"abc123"}]"#;
        let summary = redaction_summary(Some(flags), &HashSet::new()).unwrap();
        assert_eq!(summary, "[secrets: openai_api_key(high)]");
    }

    #[test]
    fn redaction_summary_lists_multiple_entries() {
        let flags = r#"[
            {"pattern":"openai_api_key","severity":"high","sha256":"abc123"},
            {"pattern":"generic_high_entropy_near_keyword","severity":"medium","sha256":"def456"}
        ]"#;
        let summary = redaction_summary(Some(flags), &HashSet::new()).unwrap();
        assert_eq!(
            summary,
            "[secrets: openai_api_key(high), generic_high_entropy_near_keyword(medium)]"
        );
    }

    #[test]
    fn redaction_summary_marks_allowlisted_hash() {
        let flags = r#"[{"pattern":"openai_api_key","severity":"high","sha256":"abc123"}]"#;
        let mut allowlist = HashSet::new();
        allowlist.insert("abc123".to_string());
        let summary = redaction_summary(Some(flags), &allowlist).unwrap();
        assert_eq!(
            summary,
            "[secrets: openai_api_key(high, future occurrences not redacted)]"
        );
    }

    #[test]
    fn anomaly_summary_is_none_when_score_is_missing() {
        // The contract query --anomalous relies on: absent score means the
        // row wasn't flagged, and no rendering happens.
        assert_eq!(anomaly_summary(None, None), None);
        assert_eq!(anomaly_summary(None, Some("irrelevant")), None);
    }

    #[test]
    fn anomaly_summary_renders_score_and_rule_names() {
        let reasons = r#"[
            {"rule":"size_spike","detail":"bytes_out=1000 exceeds 5× mean (100)"},
            {"rule":"novel_destination","detail":"destination 'x' not seen"}
        ]"#;
        let summary = anomaly_summary(Some(2.0), Some(reasons)).unwrap();
        assert_eq!(summary, "[anomaly: 2.0 -- size_spike, novel_destination]");
    }

    /// If the reasons column somehow fails to parse, the score is still a
    /// column and worth reporting — better to say "flagged, details lost"
    /// than to omit the whole row's annotation and read as unflagged.
    #[test]
    fn anomaly_summary_falls_back_to_score_alone_on_bad_reasons_json() {
        let summary = anomaly_summary(Some(1.0), Some("not json")).unwrap();
        assert_eq!(summary, "[anomaly: 1.0]");
    }

    fn stored_row(id: i64, anomaly_score: Option<f64>) -> StoredRow {
        StoredRow {
            id,
            entry: crate::db::ToolCallEntry {
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                session_id: "s".to_string(),
                agent_id: None,
                tool_name: "echo".to_string(),
                server_name: Some("srv".to_string()),
                args_json: None,
                result_json: None,
                status: "success".to_string(),
                error_message: None,
                duration_ms: Some(1),
                bytes_in: Some(0),
                bytes_out: Some(0),
                source: None,
                destination: None,
                redaction_flags: None,
                redaction_count: 0,
                anomaly_score,
                anomaly_reasons: None,
            },
            hash: String::new(),
            prev_hash: None,
        }
    }

    /// The one filter the anomalous flag adds: rows with a non-NULL
    /// anomaly_score survive, rows without one are dropped.
    #[test]
    fn anomalous_only_filters_to_flagged_rows() {
        let rows = vec![
            stored_row(1, None),
            stored_row(2, Some(1.0)),
            stored_row(3, None),
            stored_row(4, Some(3.0)),
        ];
        let filtered = filter_rows(rows, None, None, None, None, None, true);
        let ids: Vec<i64> = filtered.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![2, 4]);
    }

    /// The pre-Phase-3 behavior: `anomalous_only=false` keeps every row
    /// regardless of anomaly state, so callers that don't want the filter
    /// (default query, default export) behave exactly as before.
    #[test]
    fn anomalous_only_false_preserves_pre_phase_3_behavior() {
        let rows = vec![stored_row(1, None), stored_row(2, Some(1.0))];
        let filtered = filter_rows(rows, None, None, None, None, None, false);
        assert_eq!(filtered.len(), 2);
    }
}
