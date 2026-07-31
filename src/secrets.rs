//! Secrets detection: pattern-matching plus Shannon entropy scoring, run
//! over parsed JSON (or raw text) before anything is persisted to disk.
//!
//! This module is deliberately decoupled from `db.rs`: it takes an
//! allowlist as a plain `HashSet<String>` of sha256 hashes rather than a
//! `Connection`, so it can be unit-tested standalone and wired into
//! `proxy.rs` (which will load the set from the DB once per session) later.

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    name: String,
    regex: String,
    severity: Severity,
    #[serde(default)]
    requires_entropy_check: bool,
    #[serde(default)]
    key_name_hints: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawPatternFile {
    #[serde(rename = "pattern", default)]
    pattern: Vec<RawPattern>,
}

struct Pattern {
    name: String,
    severity: Severity,
    requires_entropy_check: bool,
    /// Lowercased once at load time so matching is a cheap `contains`
    /// against an already-lowercased key name.
    key_name_hints: Vec<String>,
    regex: Regex,
}

/// A compiled, ready-to-use set of detection patterns.
pub struct PatternSet {
    patterns: Vec<Pattern>,
}

/// Bundled default pattern set, embedded at compile time so detection works
/// out of the box with no config. See `patterns.toml` at the repo root for
/// the curated rule set and file-format docs.
const BUNDLED_PATTERNS_TOML: &str = include_str!("../patterns.toml");

impl PatternSet {
    pub fn bundled() -> anyhow::Result<Self> {
        Self::from_str(BUNDLED_PATTERNS_TOML)
    }

    pub fn from_str(raw: &str) -> anyhow::Result<Self> {
        let file: RawPatternFile = toml::from_str(raw)
            .map_err(|e| anyhow::anyhow!("failed to parse patterns file: {e}"))?;

        let mut patterns = Vec::with_capacity(file.pattern.len());
        for p in file.pattern {
            let regex = Regex::new(&p.regex)
                .map_err(|e| anyhow::anyhow!("pattern '{}' has invalid regex: {e}", p.name))?;
            patterns.push(Pattern {
                name: p.name,
                severity: p.severity,
                requires_entropy_check: p.requires_entropy_check,
                key_name_hints: p.key_name_hints.into_iter().map(|h| h.to_lowercase()).collect(),
                regex,
            });
        }
        Ok(PatternSet { patterns })
    }

    /// Scans one string value and returns every hit found in it, with
    /// overlapping matches from different patterns already merged down to
    /// one hit per physical span (see `merge_overlapping_hits`). `key_name`
    /// is the enclosing JSON object key this string was the value of, if
    /// known — `None` when scanning a JSON array element or raw/non-JSON
    /// text, where no such context exists.
    fn scan_str(&self, value: &str, key_name: Option<&str>, allowlist: &HashSet<String>) -> Vec<Hit> {
        let key_lower = key_name.map(|k| k.to_lowercase());
        let mut hits = Vec::new();

        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(value) {
                let candidate = m.as_str();
                if !passes_entropy_gate(pattern, candidate, key_lower.as_deref()) {
                    continue;
                }

                let secret_sha256 = sha256_hex(candidate);
                let allowlisted = allowlist.contains(&secret_sha256);
                hits.push(Hit {
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity,
                    secret_sha256,
                    matched_range: (m.start(), m.end()),
                    allowlisted,
                    is_heuristic: pattern.requires_entropy_check,
                });
            }
        }

        merge_overlapping_hits(hits)
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
    }
}

/// It is common and expected for more than one pattern to match the same
/// underlying secret — e.g. a value under a key named `api_key` that's
/// matched both by `aws_access_key_id` (specific, format-based) AND by
/// `generic_high_entropy_near_keyword` (heuristic: the key name satisfies
/// its hints and the value clears the entropy bar). Left unmerged, two
/// overlapping `Hit`s with identical or overlapping byte ranges would cause
/// `redact_ranges` to splice the same span twice against stale offsets —
/// corrupting the string, and in the general case (different match lengths,
/// multi-byte characters near the boundary) risking an out-of-bounds slice
/// panic. This collapses any group of mutually-overlapping hits (by
/// transitive interval merge — a chain of pairwise overlaps all folds into
/// one group, not just directly-touching pairs) into a single hit spanning
/// the full union of the group's ranges, so the entire underlying text
/// still gets redacted even if the "winning" hit's own match was narrower
/// than another hit in the group (the containment case).
///
/// Winner selection when hits in a group disagree on pattern/severity: a
/// specific, format-based pattern (`is_heuristic == false`) is preferred
/// over a heuristic one, since the heuristic's own firing condition is
/// inherently fuzzier and less informative to report; ties are broken by
/// severity, then by first-encountered (stable sort preserves original
/// pattern-iteration order for equal start positions).
fn merge_overlapping_hits(mut hits: Vec<Hit>) -> Vec<Hit> {
    if hits.len() <= 1 {
        return hits;
    }
    hits.sort_by_key(|h| h.matched_range.0);

    let mut merged = Vec::with_capacity(hits.len());
    let mut hits = hits.drain(..);

    let first = hits.next().expect("len > 1 checked above");
    let mut group_start = first.matched_range.0;
    let mut group_end = first.matched_range.1;
    let mut winner = first;

    for hit in hits {
        if hit.matched_range.0 < group_end {
            // Overlaps the running group: fold into it. The union range
            // grows even if `hit` doesn't become the new winner.
            group_end = group_end.max(hit.matched_range.1);
            winner = pick_preferred(winner, hit);
        } else {
            winner.matched_range = (group_start, group_end);
            merged.push(winner);
            group_start = hit.matched_range.0;
            group_end = hit.matched_range.1;
            winner = hit;
        }
    }
    winner.matched_range = (group_start, group_end);
    merged.push(winner);

    merged
}

fn pick_preferred(a: Hit, b: Hit) -> Hit {
    if a.is_heuristic != b.is_heuristic {
        return if a.is_heuristic { b } else { a };
    }
    if severity_rank(b.severity) > severity_rank(a.severity) {
        return b;
    }
    a
}

/// Entropy threshold (bits/char) used when key-name proximity corroborates
/// the match (e.g. this string is the value of a field named `api_key`).
/// 3.5 is the standard Gitleaks-style cutoff for mixed-charset secrets: it
/// comfortably separates random tokens (typically 4.0-6.0 bits/char) from
/// short English words or identifiers (typically 2.0-3.2), while still
/// catching hex-only secrets (~3.0-4.0) often enough given that the
/// key-name signal is already doing most of the discriminating work here.
const ENTROPY_THRESHOLD_WITH_KEY_CONTEXT: f64 = 3.5;

/// Entropy threshold used when no key name is available to corroborate
/// (raw/non-JSON payloads, or a JSON array element with no key of its own).
/// Order-0 Shannon entropy over ordinary English prose commonly lands
/// around 3.8-4.3 bits/char, so reusing the 3.5 cutoff here would flag
/// plain sentences constantly. We raise the bar and additionally require
/// the candidate to "look token-like" (`looks_token_like`, no whitespace)
/// and to not be a structurally recognizable identifier
/// (`looks_structured_identifier`) rather than searching for one threshold
/// that cleanly separates prose from secrets on entropy alone — per the
/// spec, entropy alone must never be the sole signal.
///
/// Why the structural filter can't be replaced by a higher threshold:
/// measured against a real Obsidian vault (see the vault-path regression
/// test), absolute note paths like
/// `/Computer-Science/Cryptography/CBC-Bit-Flipping-Attacks.md` score
/// 4.37-4.65 bits/char — squarely overlapping real secrets (e.g. an
/// AWS-style 40-char secret with slashes scores ~4.66). No threshold
/// separates those two populations; their difference is structural, not
/// statistical.
const ENTROPY_THRESHOLD_NO_KEY_CONTEXT: f64 = 4.3;

/// Shannon entropy is scored over the WHOLE matched substring, not a
/// sliding sub-window. Candidate matches here are already short and bounded
/// (patterns cap length, e.g. `{20,256}`), so a sliding window would buy
/// negligible precision over scoring the whole match, at the cost of an
/// extra tunable (window size, stride) to justify and test. If generic
/// key/value blobs get much larger in practice, revisit this.
fn passes_entropy_gate(pattern: &Pattern, candidate: &str, key_lower: Option<&str>) -> bool {
    if !pattern.requires_entropy_check {
        return true;
    }

    if pattern.key_name_hints.is_empty() {
        // requires_entropy_check with no key_name_hints configured: this
        // pattern's regex is already fairly specific and just wants entropy
        // as a sanity check, not key-name corroboration.
        return shannon_entropy(candidate) >= ENTROPY_THRESHOLD_WITH_KEY_CONTEXT;
    }

    let key_matches_hint = key_lower
        .map(|k| pattern.key_name_hints.iter().any(|hint| k.contains(hint.as_str())))
        .unwrap_or(false);

    if key_matches_hint {
        return shannon_entropy(candidate) >= ENTROPY_THRESHOLD_WITH_KEY_CONTEXT;
    }

    if key_lower.is_some() {
        // Key context existed but didn't match any of this pattern's hints:
        // key-name proximity is this pattern's corroborating signal by
        // design (see patterns.toml doc comment), so no match means no
        // fire, regardless of entropy. Entropy alone is never sufficient.
        return false;
    }

    // No key context at all (raw/non-JSON scan, or a bare array element):
    // fall back to a stricter, entropy-only bar instead of refusing to ever
    // fire in this mode, since over-redaction is the stated default — but
    // structurally recognizable identifiers (file paths, URLs) are exempt,
    // since they routinely clear any usable entropy bar (see the threshold
    // doc comment) and their shape is corroborating evidence AGAINST being
    // a secret, the mirror image of what key-name proximity provides for.
    looks_token_like(candidate)
        && !looks_structured_identifier(candidate)
        && shannon_entropy(candidate) >= ENTROPY_THRESHOLD_NO_KEY_CONTEXT
}

/// A crude but cheap filter for "this looks like a token, not a sentence":
/// no whitespace. Real secrets (keys, JWTs, base64 blobs) never contain
/// spaces; prose almost always does well before hitting the 20-char regex
/// minimum. This is what lets `ENTROPY_THRESHOLD_NO_KEY_CONTEXT` be usable
/// at all instead of relying on entropy to do all the work.
fn looks_token_like(s: &str) -> bool {
    !s.chars().any(|c| c.is_whitespace())
}

/// Structural pre-filter for the no-key-context fallback ONLY (key-name
/// corroborated matches and all specific, deterministic patterns are
/// unaffected): true if the candidate is recognizably a file path, URL, or
/// similar structured identifier rather than a secret. Motivated by a real
/// false-positive class found in vault stress testing — `read_multiple_notes`
/// args arrays full of note paths, every one clearing the entropy bar (see
/// `ENTROPY_THRESHOLD_NO_KEY_CONTEXT`'s doc comment for the numbers).
///
/// The rules are deliberately ANCHORED (leading path prefix) or SUFFIX
/// (file-extension shape), never "contains a slash": base64 secrets can
/// legitimately contain mid-string slashes (e.g. an AWS-style
/// `wJalrXUtnFEMI/K7MDENG/...` secret), and rejecting on bare `/` would
/// blind the fallback to exactly the raw-leaked-secret case it exists for.
/// The trade-off accepted here: a purely generic high-entropy secret that
/// is ALSO formatted like a path or ends in an extension-shaped suffix is
/// missed by this fallback — but such a value embedded under a
/// secret-suggesting key still fires via the key-context branch, and every
/// specific pattern (AWS/OpenAI/GitHub/JWT/PEM/bearer) scans it regardless.
///
/// Some checks (Windows drive prefix, `://` scheme, `~/`) are unreachable
/// with the bundled generic pattern's current charset (no `:`, `\`, or `~`)
/// but kept anyway: `PatternSet::from_str` accepts user-supplied pattern
/// files whose charsets may include them, and the checks are a few bytes'
/// comparison each.
fn looks_structured_identifier(s: &str) -> bool {
    // Anchored path prefixes: absolute, relative, home-relative.
    if s.starts_with('/')
        || s.starts_with('\\')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with("~/")
    {
        return true;
    }
    // Windows drive prefix: "C:/" or "C:\".
    let b = s.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\') {
        return true;
    }
    // URL scheme anywhere ("https://", "postgres://", ...).
    if s.contains("://") {
        return true;
    }
    // File-extension-shaped ending: a final dot-segment of 1-6 alphanumeric
    // chars with at least one letter (".md", ".tsx", ".yaml", ".7z"). Real
    // base64/base64url secrets essentially never contain dots at all
    // (JWTs do, but their dot-segments are long and they have their own
    // specific pattern), so this costs the fallback almost nothing.
    if let Some(dot) = s.rfind('.') {
        let ext = &s[dot + 1..];
        if (1..=6).contains(&ext.len())
            && ext.bytes().all(|c| c.is_ascii_alphanumeric())
            && ext.bytes().any(|c| c.is_ascii_alphabetic())
        {
            return true;
        }
    }
    false
}

/// Caps how many characters of a candidate are scored, so a pathologically
/// large string leaf can't make entropy scoring itself expensive. Far above
/// any real secret's length, so it never affects a genuine match.
const MAX_ENTROPY_SCAN_CHARS: usize = 1024;

/// Shannon entropy in bits/char, using order-0 (single-character) symbol
/// frequencies over `s`.
pub fn shannon_entropy(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().take(MAX_ENTROPY_SCAN_CHARS).collect();
    if chars.is_empty() {
        return 0.0;
    }

    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0) += 1;
    }

    let len = chars.len() as f64;
    -counts.values().map(|&count| {
        let p = count as f64 / len;
        p * p.log2()
    }).sum::<f64>()
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// One detected secret occurrence.
#[derive(Debug, Clone)]
pub struct Hit {
    pub pattern_name: String,
    pub severity: Severity,
    /// sha256 of the plaintext secret value, for cross-call correlation.
    /// The plaintext itself is never stored anywhere.
    pub secret_sha256: String,
    /// Byte range of the match within the original string value.
    pub matched_range: (usize, usize),
    /// True if this exact secret (by hash) has been marked a confirmed
    /// false positive via `--unmask`. Still reported as a hit (detection
    /// keeps recognizing the pattern) but the value is left unredacted.
    pub allowlisted: bool,
    /// True if the pattern that produced this hit required entropy
    /// scoring to fire (i.e. a fuzzy/heuristic match) rather than matching
    /// a specific, deterministic secret format. Used only to break ties in
    /// `merge_overlapping_hits` when two patterns match the same span.
    is_heuristic: bool,
}

/// Recursively walks a parsed JSON value, scanning every string leaf
/// (with its parent object key as context, when available) and redacting
/// matches in place — except allowlisted ones, which are left as-is.
/// Returns every hit found, including allowlisted ones.
pub fn scan_and_redact_json(
    value: &mut serde_json::Value,
    patterns: &PatternSet,
    allowlist: &HashSet<String>,
) -> Vec<Hit> {
    let mut hits = Vec::new();
    walk_json(value, None, patterns, allowlist, &mut hits);
    hits
}

fn walk_json(
    value: &mut serde_json::Value,
    key_name: Option<&str>,
    patterns: &PatternSet,
    allowlist: &HashSet<String>,
    hits: &mut Vec<Hit>,
) {
    match value {
        serde_json::Value::String(s) => {
            let found = patterns.scan_str(s, key_name, allowlist);
            if found.is_empty() {
                return;
            }
            *s = redact_ranges(s, &found);
            hits.extend(found);
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                // Array elements have no key name of their own.
                walk_json(item, None, patterns, allowlist, hits);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                walk_json(v, Some(k.as_str()), patterns, allowlist, hits);
            }
        }
        _ => {}
    }
}

/// Splices `[REDACTED:<pattern>]` markers into `s` at each non-allowlisted
/// hit's byte range, working right-to-left so earlier ranges stay valid as
/// later ones are spliced.
fn redact_ranges(s: &str, hits: &[Hit]) -> String {
    let mut out = s.to_string();
    let mut sorted: Vec<&Hit> = hits.iter().collect();
    sorted.sort_by(|a, b| b.matched_range.0.cmp(&a.matched_range.0));
    for hit in sorted {
        if hit.allowlisted {
            continue;
        }
        let (start, end) = hit.matched_range;
        out.replace_range(start..end, &format!("[REDACTED:{}]", hit.pattern_name));
    }
    out
}

/// Same as `scan_and_redact_json`, for raw/non-JSON payloads: no key-name
/// context exists, so only patterns that can fire without it (see
/// `passes_entropy_gate`) contribute hits here.
pub fn scan_and_redact_text(
    text: &str,
    patterns: &PatternSet,
    allowlist: &HashSet<String>,
) -> (String, Vec<Hit>) {
    let hits = patterns.scan_str(text, None, allowlist);
    if hits.is_empty() {
        return (text.to_string(), hits);
    }
    let redacted = redact_ranges(text, &hits);
    (redacted, hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_allowlist() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn bundled_patterns_load_without_error() {
        PatternSet::bundled().expect("bundled patterns.toml should parse and compile");
    }

    #[test]
    fn shannon_entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_of_uniform_string_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_of_random_looking_token_is_high() {
        let entropy = shannon_entropy("aZ9$kL2#pQ7@wR4!xN8%vT1^");
        assert!(entropy > 3.5, "expected high entropy, got {entropy}");
    }

    #[test]
    fn aws_key_fires_without_key_name_context() {
        let patterns = PatternSet::bundled().unwrap();
        let hits = patterns.scan_str(
            "the value is AKIAABCDEFGHIJKLMNOP embedded in text",
            None,
            &empty_allowlist(),
        );
        assert!(hits.iter().any(|h| h.pattern_name == "aws_access_key_id"));
    }

    #[test]
    fn github_token_fires_in_raw_text_with_no_key_context() {
        let patterns = PatternSet::bundled().unwrap();
        let token = "ghp_123456789012345678901234567890123456";
        let (redacted, hits) = scan_and_redact_text(token, &patterns, &empty_allowlist());
        assert!(hits.iter().any(|h| h.pattern_name == "github_token"));
        assert!(!redacted.contains("ghp_123456789012345678901234567890123456"));
        assert!(redacted.contains("[REDACTED:github_token]"));
    }

    #[test]
    fn generic_entropy_pattern_requires_key_name_match() {
        let patterns = PatternSet::bundled().unwrap();
        // High-entropy value, but under a key name with no relation to
        // secrets: must NOT fire, since this pattern requires key-name
        // proximity, not entropy alone.
        let hits = patterns.scan_str(
            "aZ9kL2pQ7wR4xN8vT1jM3hB6cS5dF0gY2",
            Some("description"),
            &empty_allowlist(),
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn generic_entropy_pattern_fires_with_matching_key_and_high_entropy() {
        let patterns = PatternSet::bundled().unwrap();
        let hits = patterns.scan_str(
            "aZ9kL2pQ7wR4xN8vT1jM3hB6cS5dF0gY2",
            Some("api_key"),
            &empty_allowlist(),
        );
        assert!(hits.iter().any(|h| h.pattern_name == "generic_high_entropy_near_keyword"));
    }

    #[test]
    fn generic_entropy_pattern_does_not_fire_on_low_entropy_value_under_matching_key() {
        let patterns = PatternSet::bundled().unwrap();
        let hits = patterns.scan_str(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("api_key"),
            &empty_allowlist(),
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn generic_entropy_pattern_does_not_fire_on_english_prose_with_no_key_context() {
        let patterns = PatternSet::bundled().unwrap();
        let hits = patterns.scan_str(
            "the quick brown fox jumps over the lazy dog and keeps running",
            None,
            &empty_allowlist(),
        );
        assert!(hits.is_empty(), "prose should not be flagged as a bare token: {hits:?}");
    }

    /// Regression test for a real false-positive class found in vault
    /// stress testing: `read_multiple_notes` args arrays of Obsidian note
    /// paths were redacted wholesale as `generic_high_entropy_near_keyword`
    /// hits. Array elements carry no key context (`walk_json` passes
    /// `None`), so they went through the no-key-context entropy fallback —
    /// and these literal paths (recovered from the incident DB by sha256
    /// correlation, exactly the mechanism the hashes exist for) score
    /// 4.37-4.65 bits/char, all clearing the 4.3 bar. The structural
    /// pre-filter (`looks_structured_identifier`) must reject them; no
    /// entropy threshold can (see its doc comment).
    #[test]
    fn vault_file_paths_in_bare_array_do_not_fire_as_generic_hits() {
        let patterns = PatternSet::bundled().unwrap();
        // Verbatim strings from the auditmcp-vault.db incident rows 16-20,
        // including the highest-entropy one recovered (4.65 bits/char).
        let mut value = serde_json::json!({
            "paths": [
                "/Computer-Science/Cryptography/Modes-and-Attacks/CBC-Bit-Flipping-Attacks.md",
                "/Computer-Science/Cryptography/Building-Blocks/DES-and-3DES.md",
                "/Computer-Science/Cryptography/Building-Blocks/XOR.md",
                "/Computer-Science/Cryptography/Integrity/HMAC.md"
            ],
            "prettyPrint": true
        });
        let original = value.clone();

        let hits = scan_and_redact_json(&mut value, &patterns, &empty_allowlist());

        assert!(hits.is_empty(), "vault paths must not be detected as secrets: {hits:?}");
        assert_eq!(value, original, "no path may be redacted or altered");
    }

    /// The counterweight to the vault-path test above: the no-key-context
    /// entropy fallback must STILL fire on a genuine raw secret — including
    /// one containing mid-string slashes (AWS-style secret keys are base64
    /// with `/` in the alphabet), which is exactly why
    /// `looks_structured_identifier` anchors on prefixes/suffixes instead
    /// of rejecting anything containing a slash.
    #[test]
    fn generic_secret_with_midstring_slashes_still_fires_without_key_context() {
        let patterns = PatternSet::bundled().unwrap();
        // AWS's documented example secret key shape: 40 chars, mixed case,
        // digits, mid-string slashes; 4.66 bits/char.
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let (redacted, hits) = scan_and_redact_text(secret, &patterns, &empty_allowlist());

        assert!(
            hits.iter().any(|h| h.pattern_name == "generic_high_entropy_near_keyword"),
            "raw high-entropy secret must still fire with no key context: {hits:?}"
        );
        assert!(!redacted.contains("wJalrXUtnFEMI"), "secret must be redacted: {redacted}");
    }

    #[test]
    fn looks_structured_identifier_classifications() {
        // Rejected shapes: anchored paths, URLs, extension-suffixed names.
        for s in [
            "/Computer-Science/Cryptography/Integrity/SHA-2.md",
            "./relative/build/output",
            "../parent/dir/thing",
            "~/notes/inbox",
            "C:/Users/someone/vault",
            r"C:\Users\someone\vault",
            "https://example.org/some/deep/path",
            "postgres://db.internal:5432/main",
            "CBC-Bit-Flipping-Attacks.md",
            "archive-2024-backup.7z",
        ] {
            assert!(looks_structured_identifier(s), "should be structural: {s}");
        }
        // Kept as candidates: bare tokens, secrets with mid-string slashes,
        // dot-segments that don't look like extensions.
        for s in [
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aZ9kL2pQ7wR4xN8vT1jM3hB6cS5dF0gY2",
            "ghp_123456789012345678901234567890123456",
            "abc.defghijklmnopqrstuvwx", // final dot-segment too long for an extension
        ] {
            assert!(!looks_structured_identifier(s), "should stay a candidate: {s}");
        }
    }

    #[test]
    fn scan_and_redact_json_preserves_structure_and_redacts_nested_secret() {
        let patterns = PatternSet::bundled().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"user":"alice","auth":{"headers":["x","AKIAABCDEFGHIJKLMNOP","y"]}}"#,
        )
        .unwrap();

        let hits = scan_and_redact_json(&mut value, &patterns, &empty_allowlist());
        assert_eq!(hits.len(), 1);
        assert_eq!(value["user"], "alice");
        let redacted = value["auth"]["headers"][1].as_str().unwrap();
        assert!(redacted.contains("[REDACTED:aws_access_key_id]"));
        assert_eq!(value["auth"]["headers"][0], "x");
        assert_eq!(value["auth"]["headers"][2], "y");
    }

    #[test]
    fn same_secret_hashes_identically_for_correlation() {
        let patterns = PatternSet::bundled().unwrap();
        let a = patterns.scan_str("AKIAABCDEFGHIJKLMNOP", None, &empty_allowlist());
        let b = patterns.scan_str("prefix AKIAABCDEFGHIJKLMNOP suffix", None, &empty_allowlist());
        assert_eq!(a[0].secret_sha256, b[0].secret_sha256);
    }

    #[test]
    fn allowlisted_hit_is_reported_but_not_redacted() {
        let patterns = PatternSet::bundled().unwrap();
        let hash = sha256_hex("AKIAABCDEFGHIJKLMNOP");
        let mut allowlist = HashSet::new();
        allowlist.insert(hash);

        let (redacted, hits) = scan_and_redact_text("AKIAABCDEFGHIJKLMNOP", &patterns, &allowlist);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].allowlisted);
        assert_eq!(redacted, "AKIAABCDEFGHIJKLMNOP");
    }

    #[test]
    fn pem_private_key_header_fires() {
        let patterns = PatternSet::bundled().unwrap();
        let hits = patterns.scan_str(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
            None,
            &empty_allowlist(),
        );
        assert!(hits.iter().any(|h| h.pattern_name == "pem_private_key"));
    }

    #[test]
    fn bearer_token_fires_without_key_context() {
        let patterns = PatternSet::bundled().unwrap();
        let hits = patterns.scan_str(
            "Authorization: Bearer abcdEFGH12345678ijklMNOP",
            None,
            &empty_allowlist(),
        );
        assert!(hits.iter().any(|h| h.pattern_name == "bearer_token"));
    }

    /// Regression test for the exact repro: a value matched by BOTH a
    /// specific, deterministic pattern (`aws_access_key_id`) AND the
    /// generic heuristic pattern (which fires here because the key name
    /// "api_key" satisfies its hints and the value clears the entropy
    /// bar) — an identical byte range hit twice. Before the fix, splicing
    /// both hits corrupted the string; this must collapse to exactly one
    /// clean redaction, preferring the specific pattern's name.
    #[test]
    fn identical_overlapping_hits_from_specific_and_generic_pattern_collapse_to_one_redaction() {
        let patterns = PatternSet::bundled().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(r#"{"api_key": "AKIAABCDEFGHIJKLMNOP"}"#).unwrap();

        let hits = scan_and_redact_json(&mut value, &patterns, &empty_allowlist());

        assert_eq!(hits.len(), 1, "overlapping hits on the same span must merge into one: {hits:?}");
        assert_eq!(hits[0].pattern_name, "aws_access_key_id", "specific pattern should win over the generic heuristic");
        assert_eq!(value["api_key"], "[REDACTED:aws_access_key_id]");
    }

    /// Regression test for partial (non-identical, non-containing) overlap
    /// between two patterns' matches on the same string: neither range is
    /// a subset of the other, they just share a middle section. The fix
    /// must merge them into one hit spanning the full union so the entire
    /// secret is redacted, and must not panic while doing so.
    #[test]
    fn partially_overlapping_hits_from_two_patterns_merge_without_panic() {
        let custom = r#"
[[pattern]]
name = "left_part"
regex = "AAAA[0-9]{5}"
severity = "medium"
requires_entropy_check = false

[[pattern]]
name = "right_part"
regex = "[0-9]{5}BBBB"
severity = "medium"
requires_entropy_check = false
"#;
        let patterns = PatternSet::from_str(custom).unwrap();
        // "left_part" matches "AAAA12345" (0..9); "right_part" matches
        // "12345BBBB" (4..13) -- they share bytes 4..9 but neither
        // contains the other.
        let text = "AAAA12345BBBB";
        let (redacted, hits) = scan_and_redact_text(text, &patterns, &empty_allowlist());

        assert_eq!(hits.len(), 1, "partially overlapping hits must merge into one: {hits:?}");
        assert_eq!(hits[0].matched_range, (0, 13), "merged range must be the full union");
        assert_eq!(redacted, format!("[REDACTED:{}]", hits[0].pattern_name));
    }

    /// One range fully containing another (e.g. a wide heuristic match
    /// swallowing a narrower specific match) is a distinct overlap shape
    /// from the identical-range and partial-overlap cases above and must
    /// be handled the same way: one merged hit, full span redacted, no
    /// panic, specific pattern preferred as the reported name.
    #[test]
    fn fully_contained_range_merges_and_prefers_specific_pattern() {
        let custom = r#"
[[pattern]]
name = "specific_inner"
regex = "AKIAABCDEFGHIJKLMNOP"
severity = "high"
requires_entropy_check = false

[[pattern]]
name = "generic_outer"
regex = "[A-Za-z0-9 ]{10,}"
severity = "medium"
requires_entropy_check = true
key_name_hints = ["token"]
"#;
        let patterns = PatternSet::from_str(custom).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(r#"{"token": "xx AKIAABCDEFGHIJKLMNOP yy"}"#).unwrap();

        let hits = scan_and_redact_json(&mut value, &patterns, &empty_allowlist());

        assert_eq!(hits.len(), 1, "containing ranges must merge into one: {hits:?}");
        assert_eq!(hits[0].pattern_name, "specific_inner");
        let redacted = value["token"].as_str().unwrap();
        assert!(!redacted.contains("AKIA"), "no fragment of the secret should survive: {redacted}");
    }

    /// Transitive three-hit overlap chain: A=(0,10), B=(5,15), C=(12,20).
    /// A and C do NOT directly overlap (A.end=10 < C.start=12) -- the only
    /// reason all three end up in one merged group is that B bridges them
    /// (B.start=5 < A.end=10, and C.start=12 < B.end=15). This exercises
    /// the "running group end" extension in `merge_overlapping_hits`,
    /// which the three prior (two-hit) regression tests don't reach: a
    /// merge implementation that only checks each new hit against the
    /// *original* first hit in a group (instead of the group's extended
    /// end) would wrongly keep A and C in separate groups here.
    #[test]
    fn transitive_three_way_overlap_chain_merges_via_bridging_hit() {
        let custom = r#"
[[pattern]]
name = "pat_a"
regex = "p{5}q{5}"
severity = "medium"
requires_entropy_check = false

[[pattern]]
name = "pat_b"
regex = "q{5}r{2}s{3}"
severity = "medium"
requires_entropy_check = false

[[pattern]]
name = "pat_c"
regex = "s{3}t{5}"
severity = "medium"
requires_entropy_check = false
"#;
        let patterns = PatternSet::from_str(custom).unwrap();
        // zones: p{0..5} q{5..10} r{10..12} s{12..15} t{15..20}
        // pat_a matches "ppppp qqqqq"        -> (0,10)
        // pat_b matches "qqqqq rr sss"       -> (5,15)
        // pat_c matches "sss ttttt"          -> (12,20)
        let text = "pppppqqqqqrrsssttttt";
        assert_eq!(text.len(), 20);

        let (redacted, hits) = scan_and_redact_text(text, &patterns, &empty_allowlist());

        assert_eq!(hits.len(), 1, "the bridging hit must merge all three into one group: {hits:?}");
        assert_eq!(hits[0].matched_range, (0, 20), "merged range must be the full union of all three");
        assert_eq!(redacted, format!("[REDACTED:{}]", hits[0].pattern_name));
        for fragment in ["ppppp", "qqqqq", "rr", "sss", "ttttt"] {
            assert!(!redacted.contains(fragment), "fragment '{fragment}' survived redaction: {redacted}");
        }
    }
}
