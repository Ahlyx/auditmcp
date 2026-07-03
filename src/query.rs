//! `auditmcp query` — read logged tool calls back in a readable table.

use crate::config::Config;
use crate::db::{self, StoredRow};
use chrono::{DateTime, Utc};
use std::path::Path;

pub fn run(
    config_path: &Path,
    tool: Option<String>,
    session: Option<String>,
    since: Option<String>,
    status: Option<String>,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::open_readonly(Path::new(&config.logging.db_path))?;
    let rows = db::read_all_rows(&conn)?;

    let since_cutoff = since.as_deref().map(parse_since).transpose()?;

    let filtered: Vec<StoredRow> = rows
        .into_iter()
        .filter(|r| tool.as_deref().is_none() || tool.as_deref() == Some(r.entry.tool_name.as_str()))
        .filter(|r| session.as_deref().is_none() || session.as_deref() == Some(r.entry.session_id.as_str()))
        .filter(|r| status.as_deref().is_none() || status.as_deref() == Some(r.entry.status.as_str()))
        .filter(|r| match since_cutoff {
            None => true,
            Some(cutoff) => match DateTime::parse_from_rfc3339(&r.entry.timestamp) {
                Ok(ts) => ts.with_timezone(&Utc) >= cutoff,
                // Can't parse this row's own timestamp: exclude it rather
                // than guess, since --since is meant to be a hard cutoff.
                Err(_) => false,
            },
        })
        .collect();

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
    }
    println!("({} row(s))", filtered.len());

    Ok(())
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
fn parse_since(input: &str) -> anyhow::Result<DateTime<Utc>> {
    let input = input.trim();
    let (number_part, unit) = input.split_at(input.len().saturating_sub(1));

    let amount: i64 = number_part
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --since value '{input}': expected e.g. 30m, 2h, 1d, 45s"))?;

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
}
