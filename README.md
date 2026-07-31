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

## Running multiple MCP servers: share one database

A realistic setup wraps several MCP servers, each behind its own
`auditmcp run` instance with its own config file. **The recommended
pattern is to point every config's `db_path` at the same database file.**
Concurrent `auditmcp run` processes are safe against a shared DB: each
append happens inside an exclusive write transaction (SQLite
`BEGIN IMMEDIATE`) that reads the current chain head and inserts the new
row atomically, so writers from different processes serialize into one
linear hash chain in arrival order — a second writer briefly waits (up to
5s) rather than forking the chain. `verify` walks the combined chain
exactly as it walks a single-server one, since chain linkage is purely
row-to-row and doesn't care which server a row came from.

Sharing one DB is not just a convenience: cross-server activity is the
point. An exfiltration chain that reads sensitive data via one server and
sends it out via another is only visible to `query` when both servers'
rows land in the same log. Rows are told apart by the `server_name`
column (a Phase 1 schema column) — set `[target].server_name` in each
config, since the fallback (the target command's program name, e.g. `npx`
or `python`) is usually shared across servers and won't distinguish them.

Per-server DB isolation still works if you want independent audit trails:
give each config its own `db_path` and each file carries its own complete
hash chain. You just lose the single timeline across servers, so treat it
as the opt-in exception.

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
