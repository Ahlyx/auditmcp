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
use std::path::Path;

pub fn run(
    config_path: &Path,
    tool: Option<String>,
    session: Option<String>,
    since: Option<String>,
    status: Option<String>,
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
    );

    if filtered.is_empty() {
        println!("No matching tool calls.");
        return Ok(());
    }

    // Header literals passed positionally (not inlined) to mirror the data
    // rows below and keep the column format string in one visible place.
    #[allow(clippy::print_literal)]
    {
        println!(
            "{:<5} {:<30} {:<20} {:<8} {:>9}  {}",
            "ID", "TIMESTAMP", "TOOL", "STATUS", "DUR(ms)", "PREVIEW"
        );
    }
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

        println!(
            "{:<5} {:<30} {:<20} {:<8} {:>9}  {}",
            row.id, row.entry.timestamp, row.entry.tool_name, row.entry.status, duration, preview
        );

        if verbose {
            if let Some(summary) =
                redaction_summary(row.entry.redaction_flags.as_deref(), &allowlist)
            {
                println!("      {summary}");
            }
        }
    }
    println!("({} row(s))", filtered.len());

    Ok(())
}

/// Filters rows by the criteria `query` and `export` both expose. Shared
/// so the two commands can never quietly diverge on what e.g. `--status
/// error` means. `export` is the only caller that passes `server` (query
/// has no `--server` flag), so it's always `None` from `query::run`.
pub(crate) fn filter_rows(
    rows: Vec<StoredRow>,
    tool: Option<&str>,
    session: Option<&str>,
    server: Option<&str>,
    since_cutoff: Option<DateTime<Utc>>,
    status: Option<&str>,
) -> Vec<StoredRow> {
    rows.into_iter()
        .filter(|r| tool.is_none() || tool == Some(r.entry.tool_name.as_str()))
        .filter(|r| session.is_none() || session == Some(r.entry.session_id.as_str()))
        .filter(|r| server.is_none() || server == r.entry.server_name.as_deref())
        .filter(|r| status.is_none() || status == Some(r.entry.status.as_str()))
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
}
