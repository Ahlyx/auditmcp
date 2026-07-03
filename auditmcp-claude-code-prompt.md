# auditmcp — Claude Code Project Prompt

Copy everything below into Claude Code as your initial prompt, run from `\coding projects\auditmcp`.

---

## Project Prompt

I'm building **auditmcp**, a lightweight, local-first audit logging proxy for MCP (Model Context Protocol) tool calls. It's a portfolio project for a cybersecurity concentration, but I want it built like real software: small, fast, single-binary, no required cloud dependency.

### What it does
auditmcp sits transparently between an MCP client (Claude Desktop, Claude Code, Cursor, etc.) and an MCP server. It intercepts every JSON-RPC tool call flowing through, logs it to a local SQLite database with tamper-evident hash chaining, flags likely secrets before they're stored, and flags anomalous tool-call patterns that could indicate a prompt-injected or exfiltrating agent. All data stays on the user's machine — no telemetry, no phone-home, no accounts.

### Philosophy — read before writing code
- **"It just works."** Single binary, no required config to get started, sensible defaults.
- **Lightweight over feature-complete.** We are explicitly NOT competing with enterprise MCP gateways (Kong, ContextForge, MintMCP, etc). Those require Kubernetes/OAuth/multi-tenant infra. We are the opposite: zero-infra, local-first, runs in one command.
- **Fail-open, not fail-closed by default.** The proxy must never become a blocking dependency for the agent. If logging fails, the tool call still goes through; log an "audit gap" marker instead of hanging or crashing the pipe.
- **Do one thing well.** Resist scope creep. See "Explicit non-goals" below.

### Tech stack
- **Language: Rust.** Chosen for memory safety, single static binary output, no runtime dependency, and strong async I/O support.
- `tokio` for async runtime / process + I/O handling
- `rusqlite` with WAL mode enabled for the local database
- `serde` + `toml` for config parsing
- `serde_json` for JSON-RPC message handling
- `mlua` (Lua 5.4, sandboxed) — **Phase 3 only**, do not add this dependency until Phase 3
- `sha2` for hash chaining
- `clap` for CLI argument parsing

### Target platforms
Primary target is **Windows** (the developer's main OS). Must also work on Linux (tested via Ubuntu VM) and should work on macOS without special-casing if reasonably possible. Use `cross` or `cargo-zigbuild` compatible code (avoid Windows-only or Unix-only syscalls where a cross-platform crate exists instead). Flag any platform-specific code clearly with `#[cfg(windows)]` / `#[cfg(unix)]` rather than silently breaking one platform.

---

## Build in phases. Do not skip ahead or add later-phase dependencies early.

### Phase 1 — MVP: stdio proxy + minimal logging (build this first, fully working, before anything else)

**Goal:** `auditmcp run --config config.toml -- <mcp server command>` transparently proxies a stdio-based MCP server, logs every JSON-RPC message to SQLite, and the wrapped agent behaves exactly as if auditmcp weren't there.

1. **Process supervision**: spawn the target MCP server as a child process. Pipe stdin/stdout transparently between the parent client and the child server, intercepting and parsing JSON-RPC 2.0 messages in both directions without altering them.
2. **Config file** (TOML) — fields needed at minimum:
   ```toml
   [target]
   command = ["python", "my_mcp_server.py"]  # or however the server is invoked

   [logging]
   db_path = "./auditmcp.db"
   default_tier = "minimal"  # minimal | standard | full

   [logging.tool_overrides]
   # per-tool tier overrides, e.g.
   # delete_file = "full"
   # list_directory = "minimal"
   ```
3. **SQLite schema** (WAL mode on):
   ```sql
   CREATE TABLE tool_calls (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     timestamp TEXT NOT NULL,
     session_id TEXT NOT NULL,
     agent_id TEXT,
     tool_name TEXT NOT NULL,
     server_name TEXT,
     args_json TEXT,
     result_json TEXT,
     status TEXT NOT NULL,          -- success | error | timeout
     error_message TEXT,
     duration_ms INTEGER,
     bytes_in INTEGER,
     bytes_out INTEGER,
     source TEXT,                   -- e.g. file path touched, if inferable
     destination TEXT,              -- e.g. network host called, if inferable
     redaction_flags TEXT,          -- JSON array of redaction types applied
     redaction_count INTEGER DEFAULT 0,
     anomaly_score REAL,
     anomaly_reasons TEXT,          -- JSON array, human-readable reasons
     hash TEXT NOT NULL,
     prev_hash TEXT
   );
   ```
   Note: `anomaly_score`/`anomaly_reasons` and Lua-related columns exist in the schema from day one even though the logic to populate them lands in later phases — don't do a schema migration later for this.
4. **Minimal-tier logging only in Phase 1**: log metadata (tool name, timestamps, status, duration, byte counts) with args/result truncated to a short preview (first ~200 bytes). Full/standard tiers come in Phase 2.
5. **Async, buffered writes**: tool-call interception must never block on the DB write. Use an internal channel/queue; a separate task flushes to SQLite. If the DB write fails, log a warning to stderr and continue — never block or crash the proxied session (fail-open).
6. **Hash chaining from day one** (it's cheap, don't defer it): `hash = SHA256(prev_hash + canonical_json_of(this_entry))`. Store `prev_hash` per row so the chain is verifiable later.
7. **CLI commands to implement in Phase 1**:
   - `auditmcp run --config <path> -- <command...>` — the core proxy
   - `auditmcp query [--tool <name>] [--session <id>] [--since <duration>] [--status <success|error>]` — read logs back in a readable table format
   - `auditmcp verify` — walk the hash chain from the beginning, confirm no row was altered or removed, report first broken link if any
8. **A minimal fake MCP server for testing**, included in the repo under `test-fixtures/` or similar: a trivial stdio server (Python or Rust, your choice) exposing 3 fake tools — one that echoes input, one that simulates a "delete" action, one that returns a string containing a fake API key (for later secrets-detection testing). Use this to validate the proxy end-to-end without depending on a real production MCP server.
9. **Windows + Linux dev loop**: confirm process spawning, pipe handling, and file paths work identically on both. Note any platform-specific quirks in code comments.

**Phase 1 is done when:** I can run `auditmcp run --config config.toml -- python test-fixtures/fake_server.py`, connect a real MCP client to it, make several tool calls, and then run `auditmcp query` and `auditmcp verify` and see accurate, tamper-evident logs.

---

### Phase 2 — HTTP/SSE transport, full logging tiers, secrets detection

Only start this after Phase 1 is fully working and tested.

1. **HTTP/SSE transport support**: add a reverse-proxy mode for MCP servers that speak HTTP/SSE instead of stdio, sharing the same logging pipeline as Phase 1.
2. **Standard and full logging tiers**:
   - `standard`: for JSON payloads, truncate semantically — preserve full structure/keys, cap long string values and array lengths (e.g., keep first 3 and last 3 items of a long array, with an omitted-count note). For non-JSON payloads, do head+middle+tail sampling (fixed byte windows) rather than head-only truncation.
   - `full`: no truncation.
   - Regardless of configured tier, force `full` capture for any entry where secrets detection fires or the tool call errored — anomalies should never be hidden by truncation.
3. **Secrets detection** (runs before anything is written to disk):
   - Pattern-matching against a bundled, user-updatable `patterns.yaml`/`patterns.toml` (format similar in spirit to gitleaks) covering common API key formats (OpenAI-style `sk-...`, AWS `AKIA...`, GitHub `ghp_...`, JWTs, generic `Bearer <token>` headers, etc).
   - Shannon entropy scoring as a catch-all for high-entropy token-like substrings not matched by a pattern.
   - Weight key-name proximity (e.g., a value under a key named `api_key`, `token`, `secret`, `password`) as a strong signal, combined with entropy — not entropy alone.
   - On detection: redact in place in the stored `args_json`/`result_json`, store `sha256(secret_value)` alongside the redaction (not the plaintext) so repeated use of the same secret can be correlated without ever persisting it in cleartext.
   - Default to over-redaction; provide an explicit `--unmask` flag on `query`/`export` for a user to reveal a specific redaction they've confirmed is a false positive, on their own machine only.
4. **New CLI command**: `auditmcp export --format jsonl [--since <duration>] [--unmask]` — export logs for external analysis or fine-tuning datasets.

---

### Phase 3 — Anomaly detection ("stripped-down IDS")

1. **Baseline stats per session, per tool**: rolling mean/stddev of `bytes_out`, call frequency, and set of previously-seen `destination`/`source` values.
2. **Default anomaly rules shipped out of the box** (don't require user config to get basic protection):
   - Output size for a tool call is >Nx the rolling average for that tool in this session.
   - Tool call touches a `source`/`destination` never seen before in this session.
   - Rapid repeated calls to the same tool in a short window (possible chunked exfiltration or a prompt-injection loop).
3. Populate `anomaly_score` and `anomaly_reasons` columns already present in the schema.
4. New CLI flag: `auditmcp query --anomalous` to filter to flagged entries. Consider `auditmcp watch` — a live tail of tool calls as they happen, highlighting anomalies in the terminal.

---

### Phase 4 — Lua policy layer (optional, advanced)

1. Embed `mlua` (Lua 5.4) as an **optional, sandboxed** policy layer. Sandboxing is not optional: no `os`, `io`, or `require` exposed to user policy scripts by default — only an explicit, documented API surface (e.g. `on_tool_call(tool_name, args) -> tier`, `is_secret(key_name, value) -> bool|nil`).
2. Policy script path configurable in `config.toml`. If absent, built-in defaults apply — Lua is purely an override mechanism, never required.
3. New CLI command: `auditmcp policy check <script.lua>` — lints/validates a policy script without running the full proxy, so a broken script fails loudly at check-time rather than silently at runtime.

---

## Explicit non-goals (do not build these, even if it seems easy)
- No web UI or dashboard.
- No hosted/SaaS mode, no accounts, no telemetry of any kind.
- No multi-tenant auth or RBAC — this is a single-user local tool.
- No cloud sync or remote storage backend.
- No attempt at true distributed high-availability/redundancy. Resilience = fail-open + async buffered writes + WAL mode, not clustering.
- No ML-based detection — anomaly detection stays rule-based and explainable.

## Threat model (for reference while making design decisions)
Primary concern: a prompt-injected or otherwise compromised agent using MCP tool calls to exfiltrate data or take unintended destructive actions. Secondary concern: general accountability/record-keeping ("what did my agent actually do") for compliance-style peace of mind. Not defending against: a fully malicious MCP *client* that bypasses the proxy entirely, or nation-state-level adversaries — this is a practical safety net, not a hardened security boundary.

## Distribution plan (relevant to how you structure the build)
End goal is prebuilt binaries via GitHub Releases (Windows/Linux/macOS) built through CI (GitHub Actions), no required Rust toolchain for end users. Keep this in mind for dependency choices — avoid anything that complicates static/cross-compilation. Windows binaries will be unsigned initially; note in README that SmartScreen may warn on first run.

## License
MIT.

---

## Start here
Begin with Phase 1 only. Set up the Cargo project structure, implement the stdio proxy + config parsing + SQLite logging + hash chaining + `run`/`query`/`verify` commands, and build the fake test MCP server. Confirm it works end-to-end before touching anything in Phase 2.
