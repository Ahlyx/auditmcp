# Release candidate notes

These notes cover the lifecycle, dogfood-regression, and release-coverage
changes proposed across the related pull requests. Update the release version
and date when cutting a release.

## Behavior changes

- A stdio client closing its input now enters the centralized shutdown path.
  auditmcp closes target input, gives the target a bounded chance to exit,
  drains outbound responses and pending calls, writes one clean
  `__session_end`, and waits for the database writer to flush.
- If a later process proves through the released session's OS-owned lease
  that the process is gone without a clean end, it appends
  `__session_abandoned`. That marker records last-known-alive and detection
  times; it does not claim an exact death time. A missing end marker, an old
  heartbeat, or a later session by itself remains insufficient evidence.
- Default stdio `server_name` now uses the original target executable's
  normalized basename before Windows shim wrapping. An explicit configured
  name still wins. Existing stored rows are not renamed.
- `rapid_repeats` now distinguishes identical-argument repetition from rapid
  exploration with varied arguments; broad distinct-argument fan-out has its
  own threshold. Size anomalies use a bounded robust baseline and suppress
  repeat alerts for a stable known-large response size.
- Oversized minimal-tier JSON values remain valid JSON and identify truncation
  with `__auditmcp_truncated` and `original_bytes`. An HTTP response that
  exceeds capture limits is still forwarded in full; its `result_json` holds
  a valid JSON capture notice rather than a misleading partial result.
- `verify` explains that a heartbeat gap can follow suspend/resume or
  scheduling delays. The existing gap threshold remains in place and the
  diagnostic is not a claim that tampering occurred.
- The locked Rustls dependency is updated to `0.23.45` to address
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285), a
  medium-severity TLS 1.3 handshake validation issue.

## Storage and compatibility

- No destructive migration is introduced. Existing `tool_calls` rows,
  timestamps, hashes, and session markers remain unchanged; new lifecycle
  evidence is appended through the normal hash-chain writer.
- Legacy unclosed sessions without a new liveness lease remain unknown. They
  are not rewritten or marked abandoned based on inferred timing.
- Existing JSONL export fields and database tables are unchanged. Future
  oversized minimal JSON values and HTTP capture notices have a clearer JSON
  representation; scripts that inspect those payload contents should account
  for the truncation envelope.
- New default stdio server names may differ from old raw-path values. Explicit
  `[target].server_name` values are unchanged and remain authoritative.
