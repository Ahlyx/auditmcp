//! Semantic truncation for the `standard` logging tier.
//!
//! Two entry points, matching the two payload shapes the proxy sees:
//! - `truncate_json_semantic` walks a parsed JSON value, preserving full
//!   structure/keys while capping long string values and long arrays.
//! - `truncate_raw_sampled` handles non-JSON payloads via fixed-size
//!   head+middle+tail byte windows instead of head-only truncation, so a
//!   truncated blob still gives a hint of what's in the middle and end.
//!
//! Callers are expected to run this AFTER secrets detection/redaction, so
//! truncation never slices a secret in half before it's caught, and never
//! re-exposes something already redacted by cutting around it.

use serde_json::Value;

/// Byte cap for a single string leaf under the `standard` tier. Chosen to
/// comfortably show a representative preview of typical tool args/results
/// (a file path, a short message, an error string) without ever storing
/// large blobs at this tier — `full` tier is the escape hatch when someone
/// genuinely needs the whole value.
const MAX_STRING_BYTES: usize = 500;

/// How many items to keep from the front and back of a long array. 3+3
/// matches the spec directly: enough to show shape (what kind of items,
/// whether they're uniform) from both ends without ballooning storage for
/// large result sets.
const ARRAY_KEEP_HEAD: usize = 3;
const ARRAY_KEEP_TAIL: usize = 3;

/// Recursively applies standard-tier truncation to a parsed JSON value.
/// Object keys and overall structure are never altered — only string leaf
/// values and array lengths are capped.
pub fn truncate_json_semantic(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(truncate_string(s)),
        Value::Array(arr) => Value::Array(truncate_array(arr)),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), truncate_json_semantic(v));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn truncate_string(s: &str) -> String {
    if s.len() <= MAX_STRING_BYTES {
        return s.to_string();
    }
    let end = snap_boundary(s, MAX_STRING_BYTES);
    format!("{}... [truncated, {} bytes total]", &s[..end], s.len())
}

fn truncate_array(arr: &[Value]) -> Vec<Value> {
    if arr.len() <= ARRAY_KEEP_HEAD + ARRAY_KEEP_TAIL {
        return arr.iter().map(truncate_json_semantic).collect();
    }

    let omitted = arr.len() - ARRAY_KEEP_HEAD - ARRAY_KEEP_TAIL;
    let mut out = Vec::with_capacity(ARRAY_KEEP_HEAD + ARRAY_KEEP_TAIL + 1);
    out.extend(arr[..ARRAY_KEEP_HEAD].iter().map(truncate_json_semantic));
    // A string marker rather than a typed "omission" value: keeps the
    // result valid, ordinary JSON with no new value-kind for downstream
    // readers (query output, export) to special-case.
    out.push(Value::String(format!("... {omitted} items omitted ...")));
    out.extend(
        arr[arr.len() - ARRAY_KEEP_TAIL..]
            .iter()
            .map(truncate_json_semantic),
    );
    out
}

/// Fixed-size byte windows taken from the head, middle, and tail of `text`.
/// Used for non-JSON payloads, where there's no structure to preserve and a
/// head-only preview (Phase 1's approach) would hide everything past the
/// first couple hundred bytes — e.g. an error stack trace's actual
/// exception, or the tail of a large file dump, both of which tend to
/// matter more than the middle.
///
/// Reached via `audit::Payload::Raw` at the `standard` tier. Under stdio
/// nothing produces a raw payload — stdio MCP is JSON-RPC end to end — so
/// in practice this serves the HTTP transports, where a response body for
/// a correlated `tools/call` genuinely may not be JSON.
const RAW_HEAD_BYTES: usize = 300;
const RAW_MIDDLE_BYTES: usize = 200;
const RAW_TAIL_BYTES: usize = 300;

pub fn truncate_raw_sampled(text: &str) -> String {
    let total = text.len();
    let window_total = RAW_HEAD_BYTES + RAW_MIDDLE_BYTES + RAW_TAIL_BYTES;
    if total <= window_total {
        return text.to_string();
    }

    let head_end = snap_boundary(text, RAW_HEAD_BYTES);
    let mid_start = snap_boundary(text, total / 2 - RAW_MIDDLE_BYTES / 2);
    let mid_end = snap_boundary(text, mid_start + RAW_MIDDLE_BYTES);
    let tail_start = snap_boundary(text, total - RAW_TAIL_BYTES);

    format!(
        "{}\n... [truncated, {total} bytes total; middle sample at offset {mid_start}] ...\n{}\n... [middle sample ends] ...\n{}",
        &text[..head_end],
        &text[mid_start..mid_end],
        &text[tail_start..]
    )
}

/// Snaps `idx` back to the nearest char boundary at or before it, so a
/// byte-offset window can never panic by slicing into the middle of a
/// multi-byte UTF-8 sequence. Clamps to `s.len()` first since callers here
/// sometimes compute an offset from arithmetic that could (in principle)
/// land past the end.
pub(crate) fn snap_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn short_string_untouched() {
        let v = json!("hello");
        assert_eq!(truncate_json_semantic(&v), v);
    }

    #[test]
    fn long_string_truncated_with_note() {
        let long = "x".repeat(1000);
        let result = truncate_json_semantic(&json!(long));
        let s = result.as_str().unwrap();
        assert!(s.len() < 1000);
        assert!(s.contains("truncated, 1000 bytes total"));
    }

    #[test]
    fn truncate_string_does_not_panic_on_multibyte_boundary() {
        // Each '✓' is 3 bytes; MAX_STRING_BYTES (500) is not a multiple of
        // 3, so a naive byte-slice at exactly 500 would land mid-character.
        let s = "✓".repeat(300);
        let result = truncate_string(&s);
        assert!(result.starts_with('✓'));
        assert!(result.contains("truncated"));
    }

    #[test]
    fn short_array_untouched() {
        let v = json!([1, 2, 3]);
        assert_eq!(truncate_json_semantic(&v), v);
    }

    #[test]
    fn long_array_keeps_head_and_tail_with_omitted_note() {
        let arr: Vec<i32> = (0..20).collect();
        let result = truncate_json_semantic(&json!(arr));
        let out = result.as_array().unwrap();
        assert_eq!(out.len(), ARRAY_KEEP_HEAD + ARRAY_KEEP_TAIL + 1);
        assert_eq!(out[0], json!(0));
        assert_eq!(out[1], json!(1));
        assert_eq!(out[2], json!(2));
        assert!(out[3].as_str().unwrap().contains("14 items omitted"));
        assert_eq!(out[4], json!(17));
        assert_eq!(out[5], json!(18));
        assert_eq!(out[6], json!(19));
    }

    #[test]
    fn nested_structure_preserved_recursively() {
        let long = "y".repeat(1000);
        let arr: Vec<i32> = (0..20).collect();
        let v = json!({
            "name": "tool",
            "nested": { "detail": long, "items": arr },
        });
        let result = truncate_json_semantic(&v);
        assert_eq!(result["name"], "tool");
        assert!(result["nested"]["detail"].as_str().unwrap().len() < 1000);
        assert_eq!(result["nested"]["items"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn object_keys_and_key_order_preserved() {
        let v = json!({"a": 1, "b": 2, "c": 3});
        let result = truncate_json_semantic(&v);
        assert_eq!(result, v);
    }

    #[test]
    fn short_raw_text_untouched() {
        let text = "short error message";
        assert_eq!(truncate_raw_sampled(text), text);
    }

    #[test]
    fn long_raw_text_samples_head_middle_and_tail() {
        // Three equal-sized blocks so the true midpoint of `text` falls
        // inside the middle block regardless of window sizing.
        let text = format!(
            "{}{}{}",
            "H".repeat(1400),
            "M".repeat(1400),
            "T".repeat(1400)
        );
        let result = truncate_raw_sampled(&text);
        assert!(result.len() < text.len());
        assert!(result.starts_with('H'));
        assert!(result.contains('M'));
        assert!(result.ends_with('T'));
    }

    #[test]
    fn raw_sampling_does_not_panic_on_multibyte_boundary() {
        let text = "✓".repeat(1000);
        let result = truncate_raw_sampled(&text);
        assert!(result.starts_with('✓'));
    }
}
