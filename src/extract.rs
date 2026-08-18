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

use serde_json::Value;

/// Top-level arg keys read as a destination, in the order they are checked.
/// First hit wins, which matters when a tool carries more than one of these:
/// `path` is preferred over `url` etc., because file-oriented tools are the
/// larger share of realistic MCP traffic and read cleaner in `query` output.
const DESTINATION_KEYS: &[&str] = &["path", "url", "host", "file", "target", "uri"];

/// Returns the tool call's destination if the args carry one at a
/// recognized top-level key. Returns `None` for anything else -- the audit
/// row simply keeps `destination` NULL, which is the correct signal to Rule
/// 2 that this call has no destination to compare against a baseline.
pub fn destination_from_args(args: &Value) -> Option<String> {
    let obj = args.as_object()?;
    for key in DESTINATION_KEYS {
        if let Some(Value::String(s)) = obj.get(*key) {
            if !s.is_empty() {
                return Some(s.clone());
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
            Some("notes/stress_test_1.md".to_string())
        );
    }

    #[test]
    fn extracts_url_when_no_path() {
        let args = json!({"url": "https://example.com/api"});
        assert_eq!(
            destination_from_args(&args),
            Some("https://example.com/api".to_string())
        );
    }

    /// Order in `DESTINATION_KEYS` is a contract: `path` wins over `url`
    /// when a tool somehow carries both, so a file-oriented tool reads as a
    /// file destination in `query` output.
    #[test]
    fn path_beats_url_when_both_present() {
        let args = json!({"url": "https://x.test", "path": "notes/a.md"});
        assert_eq!(destination_from_args(&args), Some("notes/a.md".to_string()));
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
            Some("stress_test_1.md".to_string())
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
}
