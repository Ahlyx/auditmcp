//! `auditmcp unmask` — mark a previously-redacted secret's hash as a
//! confirmed false positive, so future occurrences of that exact value are
//! left unredacted going forward.
//!
//! This never recovers plaintext of a past redaction: no plaintext is ever
//! stored, by design (see `secrets.rs`). Rows already written stay
//! redacted permanently — only future detections of the same value are
//! affected. This is a separate, deliberate write command, never a flag on
//! `query`/`export` (which stay pure read-only operations).

use crate::config::Config;
use crate::db;
use rusqlite::Connection;
use std::path::Path;

pub fn run(config_path: &Path, hash: &str, note: &str) -> anyhow::Result<()> {
    validate_note(note)?;

    let config = Config::load(config_path)?;
    let conn = db::open_for_write(Path::new(&config.logging.db_path))?;

    let resolved = resolve_hash(&conn, hash)?;
    let added_at = db::add_to_allowlist(&conn, &resolved.sha256, note)?;

    println!("Allowlisted secret hash: {}", resolved.sha256);
    println!(
        "  pattern: {}",
        resolved.pattern.as_deref().unwrap_or("(not seen in any logged row yet)")
    );
    println!("  note:    {note}");
    println!("  added:   {added_at}");
    println!("Future occurrences of this exact secret value will no longer be redacted.");

    Ok(())
}

#[derive(Debug)]
struct Resolved {
    sha256: String,
    pattern: Option<String>,
}

fn validate_note(note: &str) -> anyhow::Result<()> {
    if note.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "--note is required: allowlisting a secret is itself a security decision and needs a recorded reason"
        ));
    }
    Ok(())
}

/// How many example (hash, pattern) pairs to show in an ambiguous-prefix
/// error message. Just for a helpful message, not a correctness bound —
/// the exact match count comes from a separate `COUNT(DISTINCT ..)` query.
const AMBIGUOUS_MATCH_SAMPLE_LIMIT: usize = 5;

/// Resolves `input` (a full 64-hex-char sha256, or an unambiguous prefix of
/// one) against the indexed `redactions` table — the same way `git`
/// resolves a short commit hash against the hashes that actually exist in
/// the repo, but via two small indexed queries (`db::find_secret_hash_exact`,
/// `db::find_secret_hashes_by_prefix`) rather than loading every redaction
/// ever recorded into memory. A full 64-char hash is accepted even if it's
/// never been seen in any row (e.g. a user computed it independently);
/// prefix matching only applies to anything shorter, and errors (rather
/// than guessing) if it's ambiguous or matches nothing.
fn resolve_hash(conn: &Connection, input: &str) -> anyhow::Result<Resolved> {
    let input = input.trim().to_lowercase();
    if input.is_empty() || !input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "'{input}' is not a valid sha256 hash or prefix (expected hex characters only)"
        ));
    }

    if input.len() == 64 {
        let pattern = db::find_secret_hash_exact(conn, &input)?;
        return Ok(Resolved { sha256: input, pattern });
    }

    let (count, samples) = db::find_secret_hashes_by_prefix(conn, &input, AMBIGUOUS_MATCH_SAMPLE_LIMIT)?;
    match count {
        0 => Err(anyhow::anyhow!(
            "no known secret hash starts with '{input}' -- run `query --verbose` to see recorded hashes"
        )),
        1 => {
            let (sha256, pattern) = samples.into_iter().next().expect("count == 1 implies one sample");
            Ok(Resolved { sha256, pattern: Some(pattern) })
        }
        n => {
            let sample: Vec<String> = samples.iter().map(|(h, _)| h.clone()).collect();
            Err(anyhow::anyhow!(
                "'{input}' is ambiguous -- {n} known hashes start with it (e.g. {}); provide more characters",
                sample.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn temp_db() -> (Connection, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("auditmcp_unmask_test_{}.db", uuid::Uuid::new_v4()));
        let conn = db::open_for_write(&path).unwrap();
        (conn, path)
    }

    /// Seeds both `tool_calls.redaction_flags` AND the normalized
    /// `redactions` table, mirroring what `db::insert_row`'s
    /// `insert_redaction_rows` does for a real proxy-written row -- since
    /// `resolve_hash` now reads from the indexed `redactions` table, not
    /// by parsing `redaction_flags` JSON directly.
    fn seed_redaction(conn: &Connection, sha256: &str, pattern: &str) {
        let flags = format!(r#"[{{"pattern":"{pattern}","severity":"high","sha256":"{sha256}"}}]"#);
        conn.execute(
            "INSERT INTO tool_calls (timestamp, session_id, tool_name, status, redaction_flags, hash)
             VALUES ('2026-01-01T00:00:00Z', 's1', 'leak_secret', 'success', ?1, 'h')",
            params![flags],
        )
        .unwrap();
        let tool_call_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO redactions (tool_call_id, pattern, severity, secret_sha256) VALUES (?1, ?2, 'high', ?3)",
            params![tool_call_id, pattern, sha256],
        )
        .unwrap();
    }

    fn cleanup(conn: Connection, path: &std::path::Path) {
        drop(conn);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn resolves_full_hash_even_when_unseen() {
        let (conn, path) = temp_db();
        let full = "a".repeat(64);
        let resolved = resolve_hash(&conn, &full).unwrap();
        assert_eq!(resolved.sha256, full);
        assert!(resolved.pattern.is_none());
        cleanup(conn, &path);
    }

    #[test]
    fn resolves_unambiguous_prefix() {
        let (conn, path) = temp_db();
        let full = "abc123".to_string() + &"0".repeat(58);
        seed_redaction(&conn, &full, "aws_access_key_id");

        let resolved = resolve_hash(&conn, "abc123").unwrap();
        assert_eq!(resolved.sha256, full);
        assert_eq!(resolved.pattern.as_deref(), Some("aws_access_key_id"));
        cleanup(conn, &path);
    }

    #[test]
    fn rejects_ambiguous_prefix() {
        let (conn, path) = temp_db();
        let hash_a = "abc111".to_string() + &"0".repeat(58);
        let hash_b = "abc222".to_string() + &"0".repeat(58);
        seed_redaction(&conn, &hash_a, "aws_access_key_id");
        seed_redaction(&conn, &hash_b, "github_token");

        let err = resolve_hash(&conn, "abc").unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
        cleanup(conn, &path);
    }

    #[test]
    fn rejects_unknown_prefix() {
        let (conn, path) = temp_db();
        let err = resolve_hash(&conn, "deadbeef").unwrap_err();
        assert!(err.to_string().contains("no known secret hash"));
        cleanup(conn, &path);
    }

    #[test]
    fn rejects_non_hex_input() {
        let (conn, path) = temp_db();
        let err = resolve_hash(&conn, "not-hex!!").unwrap_err();
        assert!(err.to_string().contains("not a valid sha256"));
        cleanup(conn, &path);
    }

    #[test]
    fn empty_or_whitespace_only_note_is_rejected() {
        assert!(validate_note("").is_err());
        assert!(validate_note("   ").is_err());
        assert!(validate_note("false positive, verified against our own test fixture").is_ok());
    }
}
