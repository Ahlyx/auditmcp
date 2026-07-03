# auditmcp

Local-first audit logging proxy for MCP (Model Context Protocol) tool calls.
See `auditmcp-claude-code-prompt.md` for the full project spec and phased
build plan.

## Development status

**Phase 1 (stdio proxy + minimal logging) — done.**

### Testing environment note

Dev-loop testing (`cargo build`, `cargo test`, and end-to-end smoke tests
against `test-fixtures/fake_server.py`) has been run on both native Windows
(Git Bash + PowerShell) and the Ubuntu VM, per the Phase 1 requirement to
confirm process spawning, pipe handling, and file paths work identically on
both. The Linux run also carried over the Windows-generated `auditmcp.db`
(via scp) and appended to it, confirming the hash chain continues correctly
across platforms (the first Linux-generated row's `prev_hash` matched the
last Windows row's `hash`).

Also validated against a real MCP client (Claude Code, via `.mcp.json`,
through the normal server-approval flow) — `echo`, `delete_file`, and
`leak_secret` were called through natural conversation rather than manually
typed JSON-RPC, and `query`/`verify` both showed correct, intact results
afterward. Not yet covered: macOS.

## Known limitations

- **`verify` cannot detect deletion of the most recent row(s).** Hash
  chaining proves that every row from the beginning up to some point is
  unaltered and in its original order, but it can only do that by having a
  *later* row whose `id`/`prev_hash` fails to line up with what was
  deleted. If the tail of the chain is truncated (the newest N rows
  removed) there is no later row left to expose the gap — `verify` will
  report the chain as fully intact, and this stays true forever, even
  after new rows are appended in a future session (the writer just chains
  onto whatever the current last row happens to be; it has no way to know
  rows used to exist after it). This is an inherent limit of hash-chaining
  alone, not a bug — the same reason real append-only transparency logs
  need an external checkpoint/witness mechanism, which is out of scope for
  a local single-user tool. In short: `auditmcp verify` proves nothing in
  the middle of the log was altered or removed, not that nothing was
  truncated off the end.
