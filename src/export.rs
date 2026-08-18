//! `auditmcp export` — dump logged tool calls as JSONL for downstream
//! analysis/compliance tooling.
//!
//! Read-only, like `query`/`verify`. Deliberately has no `--unmask` flag:
//! `args_json`/`result_json` are emitted exactly as stored (already
//! redacted at write time, never re-processed here), and `redaction_flags`
//! is emitted in the same structured shape `query --verbose` already
//! parses (`query::StoredRedaction`) rather than re-deriving that shape
//! independently.
//!
//! NOT fail-open: if a row's `redaction_flags` is present but fails to
//! parse as the expected shape, that is corrupted data, not a quiet gap.
//! `ExportRow::from_stored` returns `Err`, which aborts the whole export --
//! an audit export that's silently missing a row is worse than one that
//! fails loudly and says why. With `--output`, the abort is also atomic
//! (see `write_atomic`): nothing at the destination path changes.
//!
//! Exit codes: unlike `verify` (which has two independently meaningful
//! nonzero codes -- tamper vs. drift -- and calls `std::process::exit`
//! itself to keep them distinct), export has exactly one failure shape:
//! "did not produce a complete export." Every error here is a plain `Err`
//! that propagates out of `run` and out of `main`, which exits 1 via the
//! standard `anyhow`/`Termination` behavior -- the same path `query`,
//! `unmask`, and `run` already use. That 1 does not collide with verify's
//! 1 ("hash-chain tampered"): each subcommand's exit codes are their own
//! documented, scoped contract, not a single shared namespace.

use crate::config::Config;
use crate::db::{self, StoredRow};
use crate::query::{filter_rows, parse_since, StoredRedaction};
use clap::ValueEnum;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ExportFormat {
    Jsonl,
}

/// One exported row. Field order mirrors `db::SELECT_ALL_SQL` (the
/// schema's own column order), except `redaction_flags`: that column is
/// exported parsed into the structured shape, not its raw JSON-in-TEXT
/// form, since a compliance/analysis consumer wants `pattern`/`severity`
/// as real JSON fields, not a string they have to parse a second time.
///
/// Every field carries an explicit `#[serde(rename)]`, even where it just
/// restates the Rust field name: this struct's JSON output is a public
/// export contract, not an implementation detail. Without the explicit
/// rename, renaming a Rust field here for internal clarity would silently
/// change what's written to disk. With it, changing the wire format
/// requires deliberately touching the rename string, not just the field.
#[derive(Serialize)]
pub struct ExportRow {
    #[serde(rename = "id")]
    pub id: i64,
    #[serde(rename = "timestamp")]
    pub timestamp: String,
    #[serde(rename = "session_id")]
    pub session_id: String,
    #[serde(rename = "agent_id")]
    pub agent_id: Option<String>,
    #[serde(rename = "tool_name")]
    pub tool_name: String,
    #[serde(rename = "server_name")]
    pub server_name: Option<String>,
    /// Exactly the stored column value, byte-for-byte — never re-parsed
    /// into a nested JSON object and re-serialized. Two independent
    /// reasons, not one: (1) "exported exactly as stored" needs to be
    /// literally true, not "same content, re-encoded"; and (2) this row's
    /// own `hash` is a SHA-256 over this exact stored string (see
    /// `db::compute_hash`) — re-serializing through serde_json can
    /// reorder object keys or normalize whitespace/escapes, which would
    /// silently produce a string that no longer reproduces the row's
    /// hash. Keeping this a raw string is what lets a consumer
    /// independently re-walk an entire export's hash chain and have it
    /// check out against the `hash`/`prev_hash` columns below.
    #[serde(rename = "args_json")]
    pub args_json: Option<String>,
    /// See `args_json` above — identical rationale.
    #[serde(rename = "result_json")]
    pub result_json: Option<String>,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "error_message")]
    pub error_message: Option<String>,
    #[serde(rename = "duration_ms")]
    pub duration_ms: Option<i64>,
    #[serde(rename = "bytes_in")]
    pub bytes_in: Option<i64>,
    #[serde(rename = "bytes_out")]
    pub bytes_out: Option<i64>,
    #[serde(rename = "source")]
    pub source: Option<String>,
    #[serde(rename = "destination")]
    pub destination: Option<String>,
    #[serde(rename = "redaction_flags")]
    pub redaction_flags: Vec<StoredRedaction>,
    #[serde(rename = "redaction_count")]
    pub redaction_count: i64,
    #[serde(rename = "anomaly_score")]
    pub anomaly_score: Option<f64>,
    #[serde(rename = "anomaly_reasons")]
    pub anomaly_reasons: Option<String>,
    #[serde(rename = "hash")]
    pub hash: String,
    #[serde(rename = "prev_hash")]
    pub prev_hash: Option<String>,
}

impl ExportRow {
    /// Fallible by design: an unparseable `redaction_flags` means this
    /// row's data is corrupted in a way that would otherwise make it
    /// silently vanish from the export with no trace. Callers must treat
    /// `Err` as "abort the whole export," not "skip this row" — see the
    /// module doc.
    pub fn from_stored(row: &StoredRow) -> anyhow::Result<Self> {
        let redaction_flags: Vec<StoredRedaction> = match row.entry.redaction_flags.as_deref() {
            None => Vec::new(),
            Some(raw) => serde_json::from_str(raw).map_err(|e| {
                anyhow::anyhow!(
                    "row id {}: redaction_flags is not valid JSON, aborting export rather than \
                     silently dropping this row's data ({e})",
                    row.id
                )
            })?,
        };

        Ok(ExportRow {
            id: row.id,
            timestamp: row.entry.timestamp.clone(),
            session_id: row.entry.session_id.clone(),
            agent_id: row.entry.agent_id.clone(),
            tool_name: row.entry.tool_name.clone(),
            server_name: row.entry.server_name.clone(),
            args_json: row.entry.args_json.clone(),
            result_json: row.entry.result_json.clone(),
            status: row.entry.status.clone(),
            error_message: row.entry.error_message.clone(),
            duration_ms: row.entry.duration_ms,
            bytes_in: row.entry.bytes_in,
            bytes_out: row.entry.bytes_out,
            source: row.entry.source.clone(),
            destination: row.entry.destination.clone(),
            redaction_flags,
            redaction_count: row.entry.redaction_count,
            anomaly_score: row.entry.anomaly_score,
            anomaly_reasons: row.entry.anomaly_reasons.clone(),
            hash: row.hash.clone(),
            prev_hash: row.prev_hash.clone(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: &Path,
    format: ExportFormat,
    tool: Option<String>,
    since: Option<String>,
    status: Option<String>,
    server: Option<String>,
    anomalous: bool,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Exhaustive match on purpose, even with one variant today: adding a
    // second format is a compile error here until this function actually
    // handles it, not a silent fall-through to JSONL.
    match format {
        ExportFormat::Jsonl => {}
    }

    let config = Config::load(config_path)?;
    let conn = db::open_readonly(Path::new(&config.logging.db_path))?;
    let rows = db::read_all_rows(&conn)?;

    let since_cutoff = since.as_deref().map(parse_since).transpose()?;
    let filtered = filter_rows(
        rows,
        tool.as_deref(),
        None,
        server.as_deref(),
        since_cutoff,
        status.as_deref(),
        anomalous,
    );

    match output {
        None => {
            // Deliberately no atomicity here (see module doc): if a row
            // fails partway through, whatever already reached stdout stays
            // there. That's acceptable for a stream, unlike a file, since
            // the nonzero exit code travels with it and nothing downstream
            // could mistake a piped stream for a self-contained artifact.
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            write_rows(&mut lock, &filtered)?;
            lock.flush()
                .map_err(|e| anyhow::anyhow!("failed to flush export output: {e}"))?;
            Ok(())
        }
        Some(path) => write_atomic(&path, &filtered),
    }
}

/// Serializes every row as one JSONL line into `writer`, stopping at the
/// first row that fails to convert (see `ExportRow::from_stored`) and
/// returning that error immediately — never skipping a row and continuing.
fn write_rows(writer: &mut dyn Write, rows: &[StoredRow]) -> anyhow::Result<()> {
    for row in rows {
        let export_row = ExportRow::from_stored(row)?;
        let line = serde_json::to_string(&export_row)
            .map_err(|e| anyhow::anyhow!("failed to serialize row id {}: {e}", row.id))?;
        writeln!(writer, "{line}")
            .map_err(|e| anyhow::anyhow!("failed to write export output: {e}"))?;
    }
    Ok(())
}

/// Writes `rows` to `path` atomically. A temp file is created in the SAME
/// directory as `path` (so the final rename can never cross a filesystem
/// boundary) and is only renamed into place once every row has serialized
/// successfully; if any row fails, the temp file is deleted and `path` is
/// left exactly as it was — absent if it was absent, unmodified if it
/// existed. Without this, an aborted export could leave a truncated JSONL
/// file sitting at the requested path that *looks* like a complete export
/// to anything that doesn't check the exit code — exactly the quiet
/// failure the loud abort in `ExportRow::from_stored` exists to prevent.
fn write_atomic(path: &Path, rows: &[StoredRow]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export");
    let temp_path = dir.join(format!(".{file_name}.tmp-{}", uuid::Uuid::new_v4()));

    let write_result = File::create(&temp_path)
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to create temp output file {}: {e}",
                temp_path.display()
            )
        })
        .and_then(|file| {
            let mut writer = BufWriter::new(file);
            write_rows(&mut writer, rows)?;
            writer.flush().map_err(|e| {
                anyhow::anyhow!(
                    "failed to flush temp output file {}: {e}",
                    temp_path.display()
                )
            })
        });

    match write_result {
        Ok(()) => std::fs::rename(&temp_path, path).map_err(|e| {
            anyhow::anyhow!(
                "failed to move completed export into place at {}: {e}",
                path.display()
            )
        }),
        Err(e) => {
            // Best-effort cleanup: if even removing the temp file fails,
            // the original error (why the export itself failed) is still
            // the one surfaced to the user -- a leftover temp file is a
            // symptom, not the headline.
            let _ = std::fs::remove_file(&temp_path);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ToolCallEntry;

    fn temp_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "auditmcp_export_test_{label}_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(dir: &Path, db_path: &Path) -> PathBuf {
        let config_path = dir.join("config.toml");
        // Forward slashes regardless of platform, so the TOML string never
        // needs backslash-escaping on Windows.
        let db_path_str = db_path.display().to_string().replace('\\', "/");
        std::fs::write(
            &config_path,
            format!("[target]\ncommand = []\n\n[logging]\ndb_path = \"{db_path_str}\"\n"),
        )
        .unwrap();
        config_path
    }

    fn sample_entry() -> ToolCallEntry {
        ToolCallEntry {
            timestamp: "2026-07-06T00:00:00Z".to_string(),
            session_id: "sess-1".to_string(),
            agent_id: None,
            tool_name: "echo".to_string(),
            server_name: Some("vault_reader".to_string()),
            args_json: Some(r#"{"msg":"hi"}"#.to_string()),
            result_json: Some(r#"{"msg":"hi"}"#.to_string()),
            status: "success".to_string(),
            error_message: None,
            duration_ms: Some(5),
            bytes_in: Some(10),
            bytes_out: Some(10),
            source: None,
            destination: None,
            redaction_flags: None,
            redaction_count: 0,
            anomaly_score: None,
            anomaly_reasons: None,
        }
    }

    fn seed(db_path: &Path, entries: &[ToolCallEntry]) {
        let mut conn = db::open_for_write(db_path).unwrap();
        for e in entries {
            db::insert_row(&mut conn, e).unwrap();
        }
    }

    fn read_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn empty_db_exports_nothing_without_error() {
        let dir = temp_test_dir("empty");
        let db_path = dir.join("audit.db");
        db::open_for_write(&db_path).unwrap(); // schema only, no rows

        let config_path = write_config(&dir, &db_path);
        let output_path = dir.join("out.jsonl");

        run(
            &config_path,
            ExportFormat::Jsonl,
            None,
            None,
            None,
            None,
            false,
            Some(output_path.clone()),
        )
        .unwrap();

        assert!(
            output_path.exists(),
            "export should still create the output file for zero rows"
        );
        let content = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(content, "", "zero rows must mean zero lines, not an error");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filters_compose_tool_and_status() {
        let dir = temp_test_dir("compose");
        let db_path = dir.join("audit.db");

        let mut a = sample_entry();
        a.tool_name = "delete_file".to_string();
        a.status = "success".to_string();
        let mut b = sample_entry();
        b.tool_name = "delete_file".to_string();
        b.status = "error".to_string();
        let mut c = sample_entry();
        c.tool_name = "echo".to_string();
        c.status = "error".to_string();
        seed(&db_path, &[a, b, c]);

        let config_path = write_config(&dir, &db_path);
        let output_path = dir.join("out.jsonl");
        run(
            &config_path,
            ExportFormat::Jsonl,
            Some("delete_file".to_string()),
            None,
            Some("error".to_string()),
            None,
            false,
            Some(output_path.clone()),
        )
        .unwrap();

        let lines = read_lines(&output_path);
        assert_eq!(
            lines.len(),
            1,
            "only the delete_file+error row should match both filters together"
        );
        let row: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(row["tool_name"], "delete_file");
        assert_eq!(row["status"], "error");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Verified against a raw SELECT against the real DB columns, not
    /// through `db::StoredRow`/`ExportRow` -- a bug that corrupted content
    /// identically on both the write path and this test's own read path
    /// would otherwise go undetected.
    #[test]
    fn redacted_row_exports_byte_identical_to_stored_columns() {
        let dir = temp_test_dir("byte_identical");
        let db_path = dir.join("audit.db");

        let mut entry = sample_entry();
        entry.args_json = Some(r#"{"key":"[REDACTED:openai_api_key]"}"#.to_string());
        entry.result_json = Some(
            r#"{"content":[{"type":"text","text":"api_key=[REDACTED:openai_api_key]"}],"isError":false}"#
                .to_string(),
        );
        entry.redaction_flags = Some(
            r#"[{"pattern":"openai_api_key","severity":"high","sha256":"aaaa1111"}]"#.to_string(),
        );
        entry.redaction_count = 1;
        seed(&db_path, &[entry]);

        let conn = db::open_readonly(&db_path).unwrap();
        let (raw_args, raw_result): (String, String) = conn
            .query_row(
                "SELECT args_json, result_json FROM tool_calls WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        drop(conn);

        let config_path = write_config(&dir, &db_path);
        let output_path = dir.join("out.jsonl");
        run(
            &config_path,
            ExportFormat::Jsonl,
            None,
            None,
            None,
            None,
            false,
            Some(output_path.clone()),
        )
        .unwrap();

        let lines = read_lines(&output_path);
        assert_eq!(lines.len(), 1);
        let exported: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();

        assert_eq!(
            exported["args_json"].as_str().unwrap(),
            raw_args,
            "args_json must be byte-identical to the raw stored column"
        );
        assert_eq!(
            exported["result_json"].as_str().unwrap(),
            raw_result,
            "result_json must be byte-identical to the raw stored column"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_filter_selects_only_matching_rows() {
        let dir = temp_test_dir("server_filter");
        let db_path = dir.join("audit.db");

        let mut a = sample_entry();
        a.server_name = Some("vault_reader".to_string());
        a.tool_name = "read_note".to_string();
        let mut b = sample_entry();
        b.server_name = Some("web_fetcher".to_string());
        b.tool_name = "fetch_url".to_string();
        seed(&db_path, &[a, b]);

        let config_path = write_config(&dir, &db_path);
        let output_path = dir.join("out.jsonl");
        run(
            &config_path,
            ExportFormat::Jsonl,
            None,
            None,
            None,
            Some("vault_reader".to_string()),
            false,
            Some(output_path.clone()),
        )
        .unwrap();

        let lines = read_lines(&output_path);
        assert_eq!(
            lines.len(),
            1,
            "only the vault_reader row should be exported"
        );
        let row: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(row["server_name"], "vault_reader");
        assert_eq!(row["tool_name"], "read_note");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Schema lock: exact serialized field names via a literal string
    /// comparison. Deliberately NOT a round-trip through `ExportRow`'s own
    /// `Deserialize` (it doesn't even derive one) -- a round-trip through
    /// the same struct would still pass even if a `#[serde(rename)]`
    /// silently drifted from its literal string, since both sides would
    /// drift together. Only a fixed literal catches that.
    #[test]
    fn export_row_schema_is_locked_to_expected_field_names() {
        let row = ExportRow {
            id: 1,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            session_id: "s1".to_string(),
            agent_id: None,
            tool_name: "echo".to_string(),
            server_name: None,
            args_json: None,
            result_json: None,
            status: "success".to_string(),
            error_message: None,
            duration_ms: None,
            bytes_in: None,
            bytes_out: None,
            source: None,
            destination: None,
            redaction_flags: vec![StoredRedaction {
                pattern: "openai_api_key".to_string(),
                severity: "high".to_string(),
                sha256: "abc123".to_string(),
            }],
            redaction_count: 1,
            anomaly_score: None,
            anomaly_reasons: None,
            hash: "h1".to_string(),
            prev_hash: None,
        };

        let expected = r#"{"id":1,"timestamp":"2026-01-01T00:00:00Z","session_id":"s1","agent_id":null,"tool_name":"echo","server_name":null,"args_json":null,"result_json":null,"status":"success","error_message":null,"duration_ms":null,"bytes_in":null,"bytes_out":null,"source":null,"destination":null,"redaction_flags":[{"pattern":"openai_api_key","severity":"high","sha256":"abc123"}],"redaction_count":1,"anomaly_score":null,"anomaly_reasons":null,"hash":"h1","prev_hash":null}"#;

        assert_eq!(serde_json::to_string(&row).unwrap(), expected);
    }

    #[test]
    fn aborted_export_leaves_no_temp_file_and_no_new_destination() {
        let dir = temp_test_dir("abort_new");
        let db_path = dir.join("audit.db");

        let mut entry = sample_entry();
        entry.redaction_flags = Some("not valid json".to_string());
        entry.redaction_count = 1;
        seed(&db_path, &[entry]);

        let config_path = write_config(&dir, &db_path);
        let output_path = dir.join("out.jsonl");
        assert!(!output_path.exists());

        let result = run(
            &config_path,
            ExportFormat::Jsonl,
            None,
            None,
            None,
            None,
            false,
            Some(output_path.clone()),
        );
        assert!(
            result.is_err(),
            "unparseable redaction_flags must abort the export"
        );
        assert!(
            !output_path.exists(),
            "destination must not spring into existence on an aborted export"
        );

        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(
            leftover.is_empty(),
            "no temp file should survive an aborted export, found: {leftover:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Beyond what was strictly asked: if the destination already existed
    /// with prior content, an aborted export must leave that content
    /// completely untouched, not just "absent if it was absent."
    #[test]
    fn aborted_export_leaves_pre_existing_destination_untouched() {
        let dir = temp_test_dir("abort_existing");
        let db_path = dir.join("audit.db");

        let mut entry = sample_entry();
        entry.redaction_flags = Some("not valid json".to_string());
        entry.redaction_count = 1;
        seed(&db_path, &[entry]);

        let config_path = write_config(&dir, &db_path);
        let output_path = dir.join("out.jsonl");
        std::fs::write(&output_path, "pre-existing content\n").unwrap();

        let result = run(
            &config_path,
            ExportFormat::Jsonl,
            None,
            None,
            None,
            None,
            false,
            Some(output_path.clone()),
        );
        assert!(result.is_err());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(
            content, "pre-existing content\n",
            "an aborted export must not touch a pre-existing destination file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Not a real assertion -- exists purely to print one concrete example
    /// row (with a genuine redaction present) for human review of the
    /// JSONL shape, run with:
    ///   cargo test export::tests::print_example_row -- --nocapture
    #[test]
    fn print_example_row() {
        let entry = ToolCallEntry {
            timestamp: "2026-07-06T10:15:00Z".to_string(),
            session_id: "sess-abc123".to_string(),
            agent_id: Some("claude-code".to_string()),
            tool_name: "leak_secret".to_string(),
            server_name: Some("vault_reader".to_string()),
            args_json: Some(r#"{}"#.to_string()),
            result_json: Some(
                r#"{"content":[{"type":"text","text":"api_key=[REDACTED:openai_api_key]"}],"isError":false}"#
                    .to_string(),
            ),
            status: "success".to_string(),
            error_message: None,
            duration_ms: Some(14),
            bytes_in: Some(2),
            bytes_out: Some(97),
            source: None,
            destination: None,
            redaction_flags: Some(
                r#"[{"pattern":"openai_api_key","severity":"high","sha256":"a1b2c3d4e5f6"}]"#.to_string(),
            ),
            redaction_count: 1,
            anomaly_score: None,
            anomaly_reasons: None,
        };
        let row = StoredRow {
            id: 42,
            entry,
            hash: "9f8e7d6c5b4a".to_string(),
            prev_hash: Some("1a2b3c4d5e6f".to_string()),
        };

        let export_row = ExportRow::from_stored(&row).unwrap();
        let line = serde_json::to_string(&export_row).unwrap();
        eprintln!("{line}");
    }
}
