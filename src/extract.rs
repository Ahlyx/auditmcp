//! Best-effort destination extraction from a tool call's arguments.
//!
//! Populates the row's `destination` column so Phase 3's "novel destination"
//! rule has material to work with. Deliberately a heuristic, not a per-tool
//! registry: the point is that a brand-new unknown MCP server still records
//! *something* useful without needing a code change. When per-tool
//! extraction lands later, it can override this fallback per tool without
//! rewriting the anomaly rule.
//!
//! Scope, plainly stated so no reader has to guess:
//!
//! - **Top-level string values only.** The keys in `DESTINATION_KEYS`, each
//!   read as `args[key]` and taken only if it is a non-empty string.
//! - **Nested keys are not walked.** A destination hidden under
//!   `{"config": {"path": "..."}}` returns `None`. Walking nested objects
//!   would find those cases, but it would also invent destinations from
//!   things like frontmatter fields that happen to be named `path` -- a
//!   quiet false positive that Rule 2 has no way to tell from a real one.
//! - **Array-valued destinations are not extracted.** `read_multiple_notes`
//!   sends `{"paths": ["a.md", "b.md"]}`; that returns `None` here. Rule 2
//!   is documented to miss array-shaped destinations.
//! - **Case-sensitive.** MCP servers use snake_case conventionally; if a
//!   real one uses `Path` or `URL`, this misses it, and the fix is to add
//!   the variant explicitly rather than lowercasing everything (which would
//!   silently start matching keys nobody intended).
//!
//! Called on the **post-redaction** args value, so a path that contained a
//! secret cannot leak plaintext through this column.
//!
//! ## Destination kind, and why it matters for Rule 2
//!
//! The extractor also reports **what shape of destination** it found —
//! filesystem or network — because Rule 2 (`novel_destination`) only
//! makes sense against network-shaped destinations under the tool's
//! threat model. Filesystem destinations are noise: writing a new note
//! in a note-taking session is the *primary use case*, and firing an
//! anomaly on every one produces 100% false positives (verified against
//! real vault traffic — see the Phase 3 dogfood in the git log). Network
//! destinations are the shape the exfiltration threat model actually
//! covers: an unexpected URL, host, or endpoint is where "data left the
//! machine" shows up.
//!
//! `target` is bucketed with network. It's genuinely ambiguous — a tool
//! could use it for either — and the tradeoff is: bucketing it with
//! filesystem silently suppresses a real signal; bucketing it with
//! network at worst produces one extra flag on an ambiguous field. Signal
//! bias over noise bias when the cost of each direction is asymmetric.

use serde_json::Value;

/// How a destination should be interpreted by the anomaly rules. Rule 2
/// treats these two categories differently; see this module's doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationKind {
    /// A filesystem path — `path`, `file`. A "new" one in a session is
    /// ordinary use of a file-oriented tool and should not fire Rule 2.
    Filesystem,
    /// A network endpoint — `url`, `host`, `uri`, `target`. A "new" one
    /// mid-session is what the exfiltration threat model actually flags.
    Network,
}

/// One extraction result: the value plus what shape of destination it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub value: String,
    pub kind: DestinationKind,
}

/// Top-level arg keys read as a destination, in the order they are
/// checked. First hit wins, which matters when a tool carries more than
/// one: `path` is preferred over `url` etc., because file-oriented tools
/// are the larger share of realistic MCP traffic and read cleaner in
/// `query` output. Each key is paired with the `DestinationKind` that
/// Rule 2 should apply to values read from it.
const DESTINATION_KEYS: &[(&str, DestinationKind)] = &[
    ("path", DestinationKind::Filesystem),
    ("file", DestinationKind::Filesystem),
    ("url", DestinationKind::Network),
    ("host", DestinationKind::Network),
    ("uri", DestinationKind::Network),
    ("target", DestinationKind::Network),
];

/// Returns the tool call's destination if the args carry one at a
/// recognized top-level key, together with the kind (filesystem vs
/// network) Rule 2 should apply to it. Returns `None` for anything else
/// -- the audit row simply keeps `destination` NULL, which is the
/// correct signal to Rule 2 that this call has no destination to compare
/// against a baseline.
pub fn destination_from_args(args: &Value) -> Option<Destination> {
    let obj = args.as_object()?;
    for (key, kind) in DESTINATION_KEYS {
        if let Some(Value::String(s)) = obj.get(*key) {
            if !s.is_empty() {
                return Some(Destination {
                    value: s.clone(),
                    kind: *kind,
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_path_from_typical_vault_tool() {
        let args = json!({"path": "notes/stress_test_1.md"});
        assert_eq!(
            destination_from_args(&args),
            Some(Destination {
                value: "notes/stress_test_1.md".to_string(),
                kind: DestinationKind::Filesystem,
            })
        );
    }

    #[test]
    fn extracts_url_when_no_path() {
        let args = json!({"url": "https://example.com/api"});
        assert_eq!(
            destination_from_args(&args),
            Some(Destination {
                value: "https://example.com/api".to_string(),
                kind: DestinationKind::Network,
            })
        );
    }

    /// Order in `DESTINATION_KEYS` is a contract: `path` wins over `url`
    /// when a tool somehow carries both, so a file-oriented tool reads as a
    /// file destination in `query` output.
    #[test]
    fn path_beats_url_when_both_present() {
        let args = json!({"url": "https://x.test", "path": "notes/a.md"});
        assert_eq!(
            destination_from_args(&args),
            Some(Destination {
                value: "notes/a.md".to_string(),
                kind: DestinationKind::Filesystem,
            })
        );
    }

    #[test]
    fn ignores_extra_args_that_are_not_destinations() {
        // Real vault traffic: `manage_tags` carries `operation` and `tags`
        // alongside `path`; neither should influence the extraction.
        let args = json!({
            "operation": "add",
            "path": "stress_test_1.md",
            "tags": ["batch-1", "volume-test"]
        });
        assert_eq!(
            destination_from_args(&args),
            Some(Destination {
                value: "stress_test_1.md".to_string(),
                kind: DestinationKind::Filesystem,
            })
        );
    }

    /// Nested walking would find this, but it would also invent
    /// destinations from frontmatter fields that happen to be named `path`.
    /// Miss-and-be-honest beats hit-and-be-wrong for Rule 2.
    #[test]
    fn nested_keys_are_not_walked() {
        let args = json!({"config": {"path": "buried.md"}});
        assert_eq!(destination_from_args(&args), None);
    }

    /// Documented Rule-2 blind spot: `read_multiple_notes` sends an array.
    #[test]
    fn array_valued_destinations_are_not_extracted() {
        let args = json!({"paths": ["a.md", "b.md", "c.md"]});
        assert_eq!(destination_from_args(&args), None);
    }

    /// Non-file, non-network tools shouldn't invent a destination just
    /// because they have some string field: `search_notes` has a `query`
    /// that is not a destination.
    #[test]
    fn tools_without_a_destination_key_return_none() {
        let args = json!({"query": "stress test", "limit": 20});
        assert_eq!(destination_from_args(&args), None);
    }

    #[test]
    fn empty_string_is_not_a_destination() {
        // An empty string is a syntactic accident, not a real target;
        // recording it as one would populate Rule 2's baseline with a value
        // that matches every call carrying an unset field.
        let args = json!({"path": ""});
        assert_eq!(destination_from_args(&args), None);
    }

    #[test]
    fn non_string_values_are_ignored() {
        let args = json!({"path": 42});
        assert_eq!(destination_from_args(&args), None);
        let args = json!({"path": ["a", "b"]});
        assert_eq!(destination_from_args(&args), None);
        let args = json!({"path": null});
        assert_eq!(destination_from_args(&args), None);
    }

    /// Args that isn't a JSON object (a tool that takes a bare string, an
    /// array, or nothing at all) has no top-level keys to read.
    #[test]
    fn non_object_args_return_none() {
        assert_eq!(destination_from_args(&json!("just a string")), None);
        assert_eq!(destination_from_args(&json!([1, 2, 3])), None);
        assert_eq!(destination_from_args(&json!(null)), None);
        assert_eq!(destination_from_args(&json!({})), None);
    }

    /// Case-sensitive by design: matching `Path` or `URL` would silently
    /// start reading keys nobody intended, and the fix if a real MCP server
    /// uses one is to add the variant explicitly.
    #[test]
    fn key_matching_is_case_sensitive() {
        assert_eq!(destination_from_args(&json!({"Path": "x.md"})), None);
        assert_eq!(destination_from_args(&json!({"URL": "https://x"})), None);
    }

    /// Filesystem keys are bucketed as filesystem: `path`, `file`. These
    /// are what Rule 2 will *not* fire on, because a new file in a
    /// file-oriented session is ordinary use.
    #[test]
    fn path_and_file_are_filesystem_kind() {
        for key in ["path", "file"] {
            let args = json!({ key: "x.md" });
            assert_eq!(
                destination_from_args(&args).unwrap().kind,
                DestinationKind::Filesystem,
                "{key} should be filesystem-shaped"
            );
        }
    }

    /// Network keys are bucketed as network: `url`, `host`, `uri`,
    /// `target`. `target` is ambiguous by nature -- some tools use it
    /// for a filesystem target, some for a network one -- and it lands
    /// with network deliberately, so that Rule 2 gets a chance on the
    /// exfiltration case rather than silently missing it.
    #[test]
    fn url_host_uri_target_are_network_kind() {
        for key in ["url", "host", "uri", "target"] {
            let args = json!({ key: "x" });
            assert_eq!(
                destination_from_args(&args).unwrap().kind,
                DestinationKind::Network,
                "{key} should be network-shaped"
            );
        }
    }
}
