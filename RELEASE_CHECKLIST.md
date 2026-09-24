# Release readiness checklist

Use this checklist after the lifecycle and dogfood pull requests have been
reviewed and integrated. Automated coverage passing on one workstation does
not replace OS CI, packaged binary checks, or the Windows client dogfood run.

## Automated checks

- [x] Local Windows: `cargo fmt --all --check`
- [x] Local Windows: `cargo clippy --all-targets --locked -- -D warnings`
- [x] Local Windows: `cargo test --locked`
- [x] Windows, Linux, and macOS CI is green for the integrated changes.
- [x] `cargo audit` is clean, or each reported advisory has a recorded
  assessment and disposition.
- [ ] Packaged release binaries pass the stdio EOF, bounded target shutdown,
  pending-call drain, single session-end, writer-drain, and subsequent verify
  smoke test.

The repository integration suite includes real-binary stdio EOF coverage,
query with `--include-synthetic` and export of clean lifecycle markers,
status/query/export scenarios, HTTP malformed-body and response-capture paths,
and copy-then-append/reset compatibility checks. Unit tests cover deterministic
heartbeat gaps and the lifecycle, recovery, JSON, identity, and anomaly
regressions from the integrated implementation.

## Windows process and shared-database checks

- [ ] Force-terminate a packaged Windows auditmcp process. Confirm it has a
  start marker and no fabricated clean end; a later process adds one recovery
  marker, repeated starts add no duplicate, and `verify` passes.
- [ ] Run two packaged processes against one database with the same logical
  server name. Kill one and confirm only its session is recovered while the
  other continues heartbeating and later ends cleanly.
- [ ] Open a database copy made by the currently released binary. Confirm its
  prior rows and hashes remain unchanged, old sessions without lease evidence
  stay unknown, query/export/verify work, a new session appends, and
  `reset --keep-old` archives the prior database.

## Codex and Ghidra manual dogfood

- [ ] Build and use the actual Windows release binary in the Codex + Ghidra
  configuration. Open Codex, inspect `__session_start`, make several Ghidra
  calls, close Codex normally, inspect the process tree and session boundary,
  then reopen and repeat several times.
- [ ] Leave one session active for multiple heartbeats. Run
  `query --include-synthetic`, `verify`, and `export`; confirm there are no
  duplicate boundaries or recovery markers.
- [ ] Repeat once with Ghidra unavailable at `GHIDRA_MCP_URL` and record the
  startup/failure behavior.

## Interpretation

A large heartbeat gap remains a verification warning because it can indicate
removed heartbeat rows, but it can also follow system suspend/resume or
scheduler delays. It is not, by itself, proof of tampering. Do not widen the
threshold to hide gaps; investigate the surrounding session and host history.

A clean `__session_end` means auditmcp ran its shutdown path. A recovered
`__session_abandoned` means a later process obtained OS lease evidence that the
session's process was gone. It does not establish the exact process death time.
Legacy unclosed sessions without lease evidence remain unknown.
