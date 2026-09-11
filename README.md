# auditmcp

A local-first audit logging proxy for MCP (Model Context Protocol) tool calls.

auditmcp sits transparently between an MCP client (Claude Code, Claude
Desktop, Cursor, …) and an MCP server. It forwards JSON-RPC traffic
byte-for-byte in both directions while logging every `tools/call` to a local
SQLite database with a tamper-evident SHA-256 hash chain, redacting likely
secrets *before* they are ever written to disk. Everything stays on your
machine: no telemetry, no accounts, no network calls, no cloud dependency.

It is deliberately not an enterprise MCP gateway. There is no Kubernetes, no
OAuth, no multi-tenancy — it is one binary, with configuration optional.

The design contract is **fail-open**: the proxy must never become a blocking
dependency of the agent it is auditing. If logging fails, the tool call still
goes through.

---

## How do I run it?

The simplest install is a portable archive from
[GitHub Releases](https://github.com/Ahlyx/auditmcp/releases). Choose the
archive for your machine:

| Platform | Archive |
|---|---|
| Windows x64 | `auditmcp-x86_64-pc-windows-msvc.zip` |
| Linux x64 | `auditmcp-x86_64-unknown-linux-musl.tar.gz` |
| macOS Intel | `auditmcp-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `auditmcp-aarch64-apple-darwin.tar.gz` |

On Linux or macOS, extract the archive and install the binary on `PATH`:

```bash
tar -xzf auditmcp-<target>.tar.gz
sudo install -m 0755 auditmcp-<target>/auditmcp /usr/local/bin/auditmcp
auditmcp --version
```

On Windows, extract the zip, copy `auditmcp.exe` to a directory on `PATH`,
then open a new terminal:

```powershell
$installDir = "$env:LOCALAPPDATA\Programs\auditmcp"
New-Item -ItemType Directory -Force $installDir | Out-Null
Copy-Item .\auditmcp-x86_64-pc-windows-msvc\auditmcp.exe $installDir
[Environment]::SetEnvironmentVariable(
  "Path",
  [Environment]::GetEnvironmentVariable("Path", "User") + ";$installDir",
  "User"
)
```

Each release includes `SHA256SUMS`, and its archives have a GitHub artifact
attestation. Windows binaries are not code-signed, so SmartScreen may show a
first-run warning.

To build from source instead, install the stable
[Rust toolchain](https://rustup.rs/):

```bash
git clone https://github.com/Ahlyx/auditmcp
cd auditmcp
cargo build --release
```

The binary lands at `target/release/auditmcp` (`auditmcp.exe` on Windows).
Python 3 is only needed for the repository's fake-server tests and examples.

For a stdio server, no auditmcp config file is required:

```bash
auditmcp run -- npx -y @some/mcp-server
```

Without `--config`, the database, key, and anchor use per-user platform state
paths. Read commands use that same default automatically:

```bash
auditmcp query
auditmcp verify
```

For custom logging, a reusable target command, or HTTP servers, copy the
example config. Relative database/key/anchor paths are resolved from the
config file's directory, not the MCP client's working directory:

```bash
cp config.example.toml config.toml
auditmcp run --config config.toml

# Trailing arguments override [target].command
auditmcp run --config config.toml -- python test-fixtures/fake_server.py
```

To put it in front of a real client, wrap the server command in your client's
MCP config. A Claude Code `.mcp.json` entry looks like:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/absolute/path/to/auditmcp",
      "args": ["run", "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

On Windows, npm-style `.cmd` shims (`npx`, `npm`, `uvx`) work as-is:
auditmcp resolves the shim on PATH and launches it via `cmd /c`, which
Windows cannot do directly.

### HTTP servers

For MCP servers that speak HTTP rather than stdio, `serve` runs one loopback
listener per upstream out of a single process:

```toml
[[server]]
name     = "github"
upstream = "http://127.0.0.1:3000/mcp"
listen   = "127.0.0.1:8787"

[[server]]
name     = "vault"
upstream = "http://127.0.0.1:3001/mcp"
listen   = "127.0.0.1:8788"
```

```bash
auditmcp serve --config config.toml
```

Then point each MCP client at `http://127.0.0.1:8787` instead of the
upstream. Each listener mirrors exactly one upstream at the origin level —
every path and method forwarded, only scheme and host swapped. Headers pass
through untouched, including `Authorization`, and **no header is ever
captured or stored**; only bodies are logged.

Each `[[server]]` also accepts `request_timeout_secs` (default 60): how long
to wait for an upstream's response headers before giving up on that request.
Body streaming is never subject to it — a long-lived event stream is normal
traffic, not a stall.

### Which servers can be proxied

| Server authentication | Through auditmcp |
|---|---|
| None | Works |
| Static header / personal access token | Works — header forwarded untouched, never stored |
| Interactive OAuth | **Not supported** — see below |

**Interactive OAuth cannot be transparently proxied, by anyone.** A local
proxy makes the client's URL and the server's advertised canonical identity
disagree by construction, and MCP clients validate that those agree before
requesting a token — so the session fails during discovery, before any token
exists. A transparent proxy and a metadata-spoofing attacker look identical
from the client's side; the check exists to stop the attack and cannot tell
the two apart. Neither side is wrong, and no choice of provider changes it.

auditmcp will not work around this by rewriting the challenge or the
resource metadata: that would make discovery succeed by defeating the
audience binding it exists to enforce.

Servers authenticated with a token you supply as a header are unaffected,
because that path never enters OAuth discovery.

`https://` upstreams work; TLS is outbound only, since auditmcp itself
listens on loopback. Certificates are verified against Mozilla's root set
compiled into the binary rather than the system store — no OpenSSL and no C
toolchain, which keeps release builds portable. The trade-off: if you are
behind a TLS-inspecting corporate proxy, its private CA is not trusted and
connections to it will fail.

Two things about a forwarded request are not byte-identical to what the
client sent, both deliberately. The `Host` header is replaced with the
upstream's own authority, because `Host` names where a request is going and
the client's copy names this proxy — forwarding it unchanged routes you to
whatever default virtual host the upstream serves. And on the deprecated
HTTP+SSE transport, the `endpoint` event's URI is rewritten, as described
above. Nothing else is altered.

Full write-up, including the mechanism, the SDK version and line, both
clients tested, and the control run:
**[docs/oauth-and-transparent-proxies.md](docs/oauth-and-transparent-proxies.md)**.

Listeners are independent: correlation state is never shared between them,
so two servers using the same JSON-RPC ids cannot be confused for each
other. Binding anywhere but loopback is refused, since auditmcp has no
authentication of its own.

All three generations of MCP-over-HTTP work through the same listener —
Streamable HTTP (2026-07-28 and 2025-03-26 through 2025-11-25) and the
deprecated HTTP+SSE transport of 2024-11-05 — because the only thing the
proxy interprets is the JSON-RPC envelope, which is identical in all of
them.

**One exception to byte-transparency, and only one.** On the legacy
HTTP+SSE transport the server's first event hands the client a URI to POST
every later message to. auditmcp rewrites that one URI to point at itself;
left alone it names the upstream, so the client would POST straight past
the proxy and the log would contain the opening connection and nothing
else. Every other byte of that stream is forwarded unchanged — verified by
running a full legacy session through the proxy and directly against the
server and diffing the two streams, which differ on exactly that one line.

Then read the log back:

```bash
auditmcp query                                      # table of tool calls
auditmcp query --verbose                            # + what was redacted and why
auditmcp query --anomalous                          # only rows the Phase 3 rules flagged
auditmcp query --include-synthetic                  # + heartbeat/session-boundary rows
auditmcp query --tool delete_file --since 2h --status error
auditmcp verify                                     # walk the hash chain (+ heartbeats, anchor)
auditmcp export --format jsonl --output audit.jsonl
auditmcp unmask <sha256> --note "confirmed false positive"
auditmcp key fingerprint                            # safe 16-character key fingerprint
auditmcp reset --yes --keep-old                     # archive the chain and start fresh
```

Add `--config config.toml` to any command when using a custom configuration.

`--since` takes a duration with a required unit: `45s`, `30m`, `2h`, `1d`.

### Diagnostics

Warnings go to stderr and are on by default, because the things auditmcp
warns about are the ways your record can be incomplete — an entry dropped
under load, the redactions index drifting, a pipe error. When logging recovers
after a dropped entry, auditmcp also writes a durable `__audit_gap` row;
`verify` reports it even if the original stderr warning is long gone. Set
`RUST_LOG` to change diagnostic verbosity:

```bash
RUST_LOG=error auditmcp run -- npx -y @some/mcp-server    # quieter
RUST_LOG=debug auditmcp run -- npx -y @some/mcp-server    # louder
```

On shutdown, auditmcp stops the target, records any still-in-flight calls
as `timeout`, and waits up to 10 seconds for the write queue to reach disk.
If entries were lost anyway it says how many and exits nonzero, so a
supervisor sees an incomplete session rather than a clean one.

Which stop mechanisms this covers, and how far each has actually been
verified rather than merely compiled:

| Mechanism | Platform | Status |
|---|---|---|
| Target process exits | all | Verified |
| `SIGTERM` | Unix | Verified — real signal, mid-session |
| `SIGINT` / Ctrl-C | Unix | Verified — real signal, mid-session |
| Ctrl-Break | Windows | Verified — real event, mid-session |
| Ctrl-C | Windows | Compiled, not verified¹ |
| Console close / system shutdown | Windows | Mechanism added², not verified¹ |
| **Windows Service stop** | Windows | **Not covered³** |

¹ These are not separately testable without closing a console or shutting
the machine down, and Windows will not deliver `CTRL_C_EVENT` to a process
group created for testing.

² Console close and system shutdown arrive with a forced kill once their
control handler returns (or a ~5s OS grace lapses). A second, blocking
control handler now holds that grace open — up to 4s — while the audit
queue drains, instead of the async path racing a near-immediate kill. The
mechanism is compiled and unit-adjacent tested, but has not been exercised
against a real console close.

³ `SERVICE_CONTROL_STOP` (what `net stop` sends) goes to a service control
handler, not a console event, so none of the above sees it. auditmcp is a
per-user command-line tool, not a Windows Service; running it as one is
unsupported. Stopping a hand-wrapped service that way can lose whatever is
still queued.

Two conditions refuse to start rather than warn, because both would mean
proxying traffic while silently failing at the job: a database that cannot
be opened (nothing would be recorded, and that fact cannot be recorded
either), and a bundled pattern set that fails to load (every secret would
be stored in the clear). The second indicates a defective build rather than
a configuration problem — the pattern set is compiled into the binary.

### Exit codes

`verify` uses seven distinct codes so a monitoring script can tell these
apart without parsing output:

| Code | Meaning |
|---|---|
| 0 | Chain intact, redactions index consistent, every enabled check passed |
| 1 | Hash-chain / HMAC verification failed — a row was altered, deleted, or reordered |
| 2 | Chain intact, but EITHER the redactions index drifted (fix with `--repair-index [--yes]`), OR this is an HMAC-protected chain and the chain key is missing/unloadable/unrecognized |
| 3 | A heartbeat gap within a session exceeded the expected cadence — likely tail truncation |
| 4 | The anchor file's own internal HMAC chain is broken |
| 5 | The anchor references chain rows that are missing or have a different hash than it recorded |
| 6 | The chain is intact, but durable `__audit_gap` markers prove one or more calls were dropped |

Every other subcommand uses plain 0/1.

---

## What does it need?

- **Rust** stable (build only — end users of a released binary need nothing).
- **Python 3** only to run `test-fixtures/fake_server.py`.
- No external services, no network access, no GPU, no data files to fetch.
  SQLite is compiled in via `rusqlite`'s bundled feature, so there is no
  system SQLite requirement.

All dependencies are pinned in `Cargo.lock`; `cargo build --locked` is
reproducible from a clean clone.

**Platforms.** CI tests Windows, Linux, and macOS. Release builds cover
Windows x64, static Linux x64, macOS Intel, and macOS Apple silicon, with a
packaged-binary smoke test on each runner. macOS has not been manually
exercised. Windows binaries are unsigned, so SmartScreen may warn on first
run.

---

## What state is it in?

The 0.1 release line is feature-complete for its intended scope: a local,
single-user audit proxy with optional configuration. Phases 1, 2, 3, and
3.5 are complete. The proposed Phase 4 policy gateway is intentionally
cancelled; auditmcp records and explains activity but never decides whether
a tool call is allowed.

### Working

- **stdio proxy** — spawns the target MCP server, pipes stdin/stdout
  transparently, intercepts `tools/call` request/response pairs. Non-tool
  traffic (`initialize`, `tools/list`, notifications) is forwarded but not
  logged, since this tool audits *tool calls*. Child stderr is inherited so
  tracebacks still reach your terminal. Top-level JSON-RPC **batches** are
  audited per element on both transports, matching protocol revisions from
  2025-03-26 onward that allow (or mandate) batching.
- **Hash-chained SQLite log** (WAL mode) — `hash = SHA256(prev_hash +
  canonical_json(entry))`, written from a dedicated writer thread behind a
  channel so interception never blocks on disk I/O.
- **Logging tiers** — `minimal` (200-byte preview), `standard` (structure
  preserving: full keys, string values capped at 500 bytes, long arrays kept
  as first 3 + last 3 with an omitted count), `full` (untruncated).
  Per-tool overrides via `[logging.tool_overrides]`. Tier is **force-escalated
  to `full`** whenever secrets detection fires or the call errored, so
  anomalies can never be hidden by truncation.
- **Secrets detection** — runs before anything is persisted. Ten bundled
  patterns (AWS access key, OpenAI, GitHub, Slack, Google, Stripe, JWT,
  bearer token, PEM private key, plus a generic high-entropy-near-keyword
  heuristic), compiled into the binary from `patterns.toml` so detection
  works with zero config. Shannon entropy scoring is weighted by key-name
  proximity rather than used alone. Overlapping hits from specific and
  heuristic patterns merge into one redaction. Only `sha256(secret)` is
  stored — never the plaintext — so the same leaked value can be correlated
  across rows.
- **`unmask`** — marks a secret's hash as a confirmed false positive so
  *future* occurrences stop being redacted. Deliberately a separate,
  audited write requiring a `--note`, rather than a `--unmask` flag on
  `query`/`export`. It never recovers past plaintext, because none was ever
  stored.
- **`export`** — JSONL, with the same filters as `query` plus `--server`.
  Writes atomically via temp-file rename when `--output` is given. Fails
  loudly rather than silently emitting an incomplete audit export.
- **`verify --repair-index`** — rebuilds the derived redactions index from
  `redaction_flags` (the source of truth). Dry run unless `--yes`; only ever
  touches the derived index, never `tool_calls` or any hash. Refuses to run
  at all if chain verification failed.
- **Multi-server support** — see below.
- **Anomaly detection (Phase 3)** — three session-scoped rules, all
  rule-based and explainable, tuned against real vault dogfood.
  `size_spike` fires when `bytes_out` for a tool exceeds 5× its running
  mean once at least five prior samples have armed the baseline
  (Welford's for the mean). `novel_destination` fires when a
  **network-shaped** destination (`url`, `host`, `uri`, `target`) not
  seen in this session appears after a non-empty baseline — filesystem
  destinations (`path`, `file`) are deliberately excluded because
  writing a new note is the primary use case of a note-taking tool, and
  firing on every new file path produced a 100% false-positive rate in
  dogfood. `rapid_repeats` fires when the last five calls to the same
  tool land inside a 10-second window, and then **cools down** for that
  tool for the same window — one burst produces one flag, not one per
  call from the fifth onward. Anomaly state is per session, held on the
  `Session` itself; scoring runs at write time so `query --anomalous`
  reduces to a `WHERE anomaly_score IS NOT NULL` filter — same filter
  available on `export --anomalous`. Populates the `anomaly_score` and
  `anomaly_reasons` columns that were in the schema from day one.
- **Best-effort destination extraction.** Populates the `destination`
  column from top-level string args under `path`, `url`, `host`, `file`,
  `target`, or `uri`, and tags each with a *kind* (filesystem or
  network) that rule 2 above consults. Runs after redaction, so a path
  that contained a secret cannot leak plaintext through this column.
  Nested keys aren't walked and array-valued destinations aren't
  extracted — both would trade quiet false positives for more coverage —
  so tools like `read_multiple_notes` don't populate `destination` and
  rule 2 is documented to miss those.
- **Chain hardening (Phase 3.5)** — HMAC-keyed hash chain, randomized-cadence
  heartbeats with genesis-fixed cadence bounds, an external per-platform
  anchor file, three new `verify` exit codes, `auditmcp key`, and
  `auditmcp reset`. See the "Chain hardening" section below for the full
  write-up. As of 0.1.2 a legacy Phase 1-3 database is no longer run or
  verified in place -- see "Migrating a Phase 1-3 (legacy) chain".

### Deliberately not included

- **`auditmcp watch`** — a live tail of tool calls as they happen, with
  anomalies highlighted. `query --anomalous` and `export --anomalous`
  provide the same evidence without another long-running interface to
  maintain.
- **Runtime-custom secret patterns.** `patterns.toml` is compiled into the
  binary so a fresh install works consistently with no pattern files or
  configuration to maintain. Changes belong in a reviewed release.
- **Phase 4 / Lua policy enforcement.** Blocking, approvals, and embedded
  policy scripts would turn a small audit tool into a gateway. That is a
  different product and will not be added here.
- **Service/daemon installers.** auditmcp is launched by the MCP client that
  uses it. System-wide lifecycle management is outside the single-user
  scope.

This is the stopping point: the auditing, redaction, anomaly, verification,
packaging, and maintenance paths are complete. Further work is maintenance
(security fixes, dependency updates, protocol compatibility, and bugs found
by real users), not another planned feature phase. See [RESULTS.md](RESULTS.md)
for the closeout record and [SECURITY.md](SECURITY.md) for vulnerability
reporting.

The non-JSON payload path — `truncate::truncate_raw_sampled` and
`secrets::scan_and_redact_text` — handles HTTP response bodies that aren't
JSON (an upstream 502 HTML page, a stack trace, an unexpected content
type). Stdio MCP is JSON-RPC end to end so it never exercises this path;
`serve` does, whenever the upstream returns non-JSON.

### How it has been verified

`cargo test` runs 285 tests covering the hash chain (including concurrent
writers against a shared DB and interleaved multi-server chains), secrets
detection and its false-positive cases, truncation UTF-8 boundary safety,
export fidelity, unmask hash resolution, `verify` exit codes and
`--repair-index` semantics, the HTTP transport — SSE parser
resynchronization after an oversized event, mixed-style event terminators,
per-listener id isolation so two upstreams reusing the same JSON-RPC ids
never cross-attribute, `Host`-header rewriting to the upstream authority,
and non-JSON upstream responses being logged as errors with their body —
Phase 3's anomaly detection: destination extraction and kind tagging, all
three rules' arm/fire/silent cases, and rule 3's cooldown (one burst yields
one flag, with a second burst after the window firing again) — and Phase
3.5's chain hardening: HKDF subkey derivation and salting, the bootstrap
decision table (fresh/existing/wrong-key/refused), heartbeat gap detection
within and across sessions, the anchor's own internal chain plus its
cross-check against the database, torn-tail recovery and lock-file
serialization for the anchor, and `reset`'s archive-vs-delete behavior.

Beyond unit tests, the proxy has been exercised end to end on **native
Windows** (Git Bash + PowerShell) and on an **Ubuntu VM**. The Linux run
carried over the Windows-generated `auditmcp.db` and appended to it,
confirming the hash chain continues correctly across platforms — the first
Linux-written row's `prev_hash` matched the last Windows row's `hash`.

It has also been driven by a **real MCP client** (Claude Code, via
`.mcp.json`, through the normal server-approval flow) rather than
hand-typed JSON-RPC: `echo`, `delete_file`, and `leak_secret` were invoked
through ordinary conversation, and `query` / `verify` both showed correct,
intact results afterward.

CI runs fmt, clippy (warnings denied), the test suite, and an end-to-end
smoke test against the fake server on Windows, Linux, and macOS.

**Not covered:** manual macOS testing, and any real-world load beyond
hand-driven sessions.

---

## Running multiple MCP servers: share one database

A realistic setup wraps several MCP servers, each behind its own `auditmcp
run` instance with its own config file. **The recommended pattern is to point
every config's `db_path` at the same database file.**

Concurrent `auditmcp run` processes are safe against a shared DB: each append
happens inside an exclusive write transaction (SQLite `BEGIN IMMEDIATE`) that
reads the current chain head and inserts the new row atomically, so writers
from different processes serialize into one linear hash chain in arrival
order — a second writer briefly waits (up to 5s) rather than forking the
chain. `verify` walks the combined chain exactly as it walks a single-server
one, since chain linkage is purely row-to-row and doesn't care which server a
row came from.

Sharing one DB is not just a convenience: cross-server activity is the point.
An exfiltration chain that reads sensitive data via one server and sends it
out via another is only visible to `query` when both servers' rows land in
the same log. Rows are told apart by the `server_name` column — set
`[target].server_name` in each config, since the fallback (the target
command's program name, e.g. `npx` or `python`) is usually shared across
servers and won't distinguish them.

Per-server DB isolation still works if you want independent audit trails:
give each config its own `db_path` and each file carries its own complete
hash chain. You just lose the single timeline across servers, so treat it as
the opt-in exception.

---

## Known limitations

**`verify` cannot detect deletion of the most recent row(s), from hashing
alone.** Hash chaining proves that every row from the beginning up to some
point is unaltered and in its original order, but it can only do that by
having a *later* row whose `id`/`prev_hash` fails to line up with what was
deleted. If the tail of the chain is truncated (the newest N rows removed)
there is no later row left to expose the gap from hashing alone.

Phase 3.5 ("Chain hardening", below) narrows this gap without closing it
completely: heartbeats make a **within-session** truncation visible (the
gap between two surviving heartbeats gets too wide), and the external
anchor makes a **whole-database replace** visible (the anchor, stored
elsewhere, still names a row the swapped-in database doesn't have). What
remains uncovered is an attacker who has both DB write access and the
anchor file, and who truncates precisely between two heartbeats without
ever letting a wider session boundary or anchor tick expose the gap — see
the updated threat model below for the exact boundary.

This is an inherent limit of hash-chaining alone, not a bug — it is the same
reason real append-only transparency logs need an external
checkpoint/witness mechanism.

**Very large responses are recorded only in part.** Over HTTP, response
bodies stream through to the client untouched however large they are, but
the copy kept for the log is capped at 1 MiB. A response past that is
forwarded in full and its row records the size and says plainly that the
content was not captured. The cap is on auditing, never on forwarding —
buffering a response to finish auditing it would make the proxy a blocking
dependency of the agent, which is the one thing it must not become.

**Results delivered as tasks are not recorded.** When a server returns a
handle from the `io.modelcontextprotocol/tasks` extension instead of a
result — normal for long-running work — the real outcome arrives later via
`tasks/get`. That is not a `tools/call`, so **auditmcp forwards it and does
not log it.** Not because it can't see it: those messages cross the proxy
like any others, and nothing today correlates them back to the call that
started the task.

Such calls are recorded with `status = "deferred"` rather than `success`,
so this gap is visible in the data rather than only in this file — query
them with `auditmcp query --status deferred`. The row keeps the full
handle including its `taskId`, which is the thread back to the outcome if
you need to chase it. Treat a `deferred` row as *this tool ran and its
result is not in this log*.

**Secrets detection is heuristic.** It defaults to over-redaction and will
produce false positives; `unmask` is the escape hatch. It will also miss
credential formats not in `patterns.toml` that don't clear the entropy bar.

**The proxy is not a security boundary.** Per the threat model, it defends
against a prompt-injected or compromised *agent* misusing tool calls. It does
not defend against a malicious MCP *client* that simply bypasses the proxy,
and it cannot audit what never flows through it.

---

## Chain hardening (Phase 3.5)

The plain hash chain (`hash = SHA256(prev_hash + canonical_json(entry))`)
proves interior integrity but has two gaps: it's **publicly verifiable and
therefore forgeable** by anyone with database write access, and **tail
truncation is invisible** to hashing alone (see Known limitations above).
Phase 3.5 closes both, while staying inside the project's philosophy — local
first, one binary, optional config, fail-open, no cloud. None of it can ever
block a `tools/call`; every new mechanism here is warn-and-continue at
runtime. Only `auditmcp run`'s startup and `auditmcp verify` are strict.

**HMAC-keyed hash chain.** `hash` is now `HMAC-SHA256(chain_key, prev_hash +
canonical_json(entry))` for any database created under Phase 3.5 — same
32-byte size, no schema change, but no longer forgeable without the key.
`chain_key` and a second `anchor_key` are both derived from one root key via
HKDF-SHA256, salted with the database's own `db_uuid` so the same root key
never produces the same effective keys across two databases. The root key
lives in the platform state directory by default, under a per-database name,
and is generated automatically the first time `auditmcp run` starts against a
database that doesn't exist yet, with 0600/0700 permissions on Unix (Windows
has no POSIX bits; see the caveat under `auditmcp key` below). **There is no
key rotation** — a deliberate scope cut, not a TODO: rotating would need
multi-key verification and `kid`-style migration semantics that don't earn
their weight for a single-user tool. `auditmcp reset --keep-old` is the
supported way to get a fresh key.

Startup is strict about the key, because a wrong or missing one means `run`
cannot produce a valid chain: a database with no key present refuses to
start; a database whose HMAC-protected first row doesn't verify under the
key that *is* present also refuses to start (wrong key, or a corrupted key
file).

**Heartbeats.** With `[heartbeat].enabled = true` (the default), synthetic
rows are appended at a randomized cadence (`cadence_min_secs`..`cadence_max_secs`,
default 30–90s) — `tool_name = "__heartbeat"`, plus `__session_start` at
`run` startup and `__session_end` during the graceful shutdown window. The
cadence range is fixed once, at the chain's genesis, in `chain_metadata`; an
attacker with DB write access can't lower it retroactively to hide a gap,
because doing so would itself break the HMAC of those genesis rows.
`verify` flags any gap between two heartbeats in the same session that
exceeds `cadence_max_secs × 1.5` (fudge factor for scheduler jitter). These
rows are chain-integrity plumbing, not tool-call activity: `query` hides
them by default (`--include-synthetic` shows them), `export` always
includes them, and Phase 3's anomaly rules never see them.

**State paths.** Without a config, the database is `audit.db` under the
platform state directory: `%LOCALAPPDATA%\auditmcp` on Windows,
`~/Library/Application Support/auditmcp` on macOS, and
`${XDG_STATE_HOME:-$HOME/.local/state}/auditmcp` on Linux. Default key and
anchor filenames include a stable identifier derived from the resolved
database path. Separate databases therefore never share reset-sensitive files
or one anchor chain. `auditmcp key path` prints the exact key location.

**External anchor.** With `[anchor].enabled = true` (the default), a small
JSONL file — itself an HMAC chain, keyed by `anchor_key` — is appended to
every `cadence_secs` (default 300s) outside the database, at a per-platform
default per-database path unless `[anchor].path` overrides it.

Each line names the chain's current tail (`chain_last_id`, `chain_last_hash`)
and chains from the previous line's `anchor_hmac`. Writes are serialized
across processes by a lock file next to the anchor (several `auditmcp run`
instances sharing a `db_path` is the recommended setup, and two of them
appending concurrently would otherwise chain from the same tail), and a
torn final line from a crash is repaired on the next append rather than
wedging every future tick. `verify` checks the
anchor's own internal chain, then cross-checks every entry against the live
database — a row the anchor names must still exist with the hash the anchor
recorded. Anchoring needs a key, which every runnable chain now has.

**`auditmcp key`** — a deliberately small operational surface:

```bash
auditmcp key path                         # print the resolved key file path
auditmcp key fingerprint                  # sha256(root_key)[:16] -- safe to share
auditmcp key backup <dest>                # atomic copy, same 0600/0700 perms
auditmcp key backup <dest> --force        # ... replacing an existing file at <dest>
```

No `key generate` (automatic on first run against a new database), no `key
rotate` (see above), no `key import`.

**`auditmcp reset`** — the only supported "start fresh" / migration path:

```bash
auditmcp reset --yes               # delete DB, key, and anchor; fresh chain
auditmcp reset --yes --keep-old    # archive them (audit.db.reset-bak-<timestamp>), fresh chain
```

Refuses to run without `--yes`. `--keep-old` archives with a timestamped
suffix rather than deleting; either way, a brand-new HMAC-protected chain
(new key, new `db_uuid`) is bootstrapped immediately after.

**Migrating a Phase 1-3 (legacy) chain.** There is no in-place upgrade — a
retrofit would either need the user's blessing on some default key (bad UX)
or produce a chain mixing hash schemes (bad design), and both are rejected.

**Breaking change in 0.1.2:** a legacy chain is no longer *run* or
*verified* in place either. `run` refuses to start on a database whose
`chain_metadata` cannot establish that it is HMAC-protected, and `verify`
reports it as tamper (exit 1) rather than walking it unkeyed.

The reason is that "legacy" was indistinguishable from "someone deleted the
metadata." The unkeyed scheme needs no key to produce, so continuing under
it meant a single `DELETE FROM chain_metadata WHERE key='hmac_version'`
silently downgraded a protected chain to a forgeable one — and `verify`
would still exit 0 on a database replaced wholesale by a fabricated legacy
chain, ignoring the key file and anchor sitting right next to it.

The supported path is now the one that was already recommended:
`auditmcp reset --keep-old` archives the old chain and starts a fresh one
with HMAC, heartbeats, and the anchor all enabled. The archived file is
untouched, so a genuine pre-3.5 chain can still be read with any SQLite
client and verified with auditmcp 0.1.1 if you need its original checks.

**Config additions**, all optional and default on — see
[`config.example.toml`](config.example.toml) for the full block with
comments:

```toml
[chain]
# key_path = ""       # empty/omitted = per-database platform default

[heartbeat]
enabled = true
cadence_min_secs = 30
cadence_max_secs = 90

[anchor]
enabled = true
path = ""          # empty = per-database platform default
cadence_secs = 300
```

**Explicit non-goals for this phase:** key rotation, multi-anchor (writing
the anchor to more than one location), OS keychain integration, OS-level
append-only file bits (`chattr +a` / `chflags uappnd` — a possible future
`auditmcp harden`), external witnessing or any network/remote anchor, and
any policy enforcement or blocking — this is audit hardening, not a gateway.

---

## Threat model

Primary concern: a prompt-injected or otherwise compromised agent using MCP
tool calls to exfiltrate data or take unintended destructive actions.
Secondary: general accountability — "what did my agent actually do."

**What Phase 3.5 adds defense against**, on top of the plain hash chain: an
attacker with database write access but not the key file can no longer
forge or extend the chain (HMAC), and can no longer silently truncate the
tail of an in-progress session without either a heartbeat-gap or a missing
`__session_end` becoming visible (heartbeats), or the externally-stored
anchor disagreeing with the (now-shorter) database (anchor) — provided the
anchor file itself wasn't also under that attacker's control. An attacker
with DB write access *and* anchor write access, but still without the key
file, cannot forge either chain, since both are HMAC-keyed.

**Still out of scope:** full-machine compromise (an attacker who reads the
key file directly has everything needed to forge both chains), an
adversary with both the key file and DB write access, and a truncation
precise enough to avoid ever crossing a heartbeat or anchor tick. None of
this defends against a fully malicious MCP client that bypasses the proxy
entirely, or nation-state-level adversaries. This is a practical safety net,
not a hardened boundary.

---

## Development

The normal local gate is:

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

To publish a release, update the version in `Cargo.toml`, merge it with green
CI, then create and push a matching annotated tag:

```bash
git tag -a vX.Y.Z -m "auditmcp vX.Y.Z"
git push origin vX.Y.Z
```

The release workflow rejects a tag that disagrees with `Cargo.toml`, builds
and smoke-tests all four archives, attests them, writes `SHA256SUMS`, and
publishes the GitHub Release.

### Troubleshooting

**rust-analyzer may show phantom `E0308`/`E0608` squiggles in async/
tokio-heavy files** (`http/`, `proxy.rs`, `anchor.rs`, `shutdown.rs`,
`query.rs`, `truncate.rs`). These have been checked against the compiler
and are not real: `cargo check --all-targets --all-features` is the
source of truth and passes clean. rust-analyzer's own background
`cargo check` (its "flycheck," visible under `target/flycheck0`) also
comes back clean, and its proc-macro server log shows no load failures,
panics, or ABI mismatches — so this isn't a proc-macro or config issue
either. The one concrete lead found so far is that rust-analyzer's
language server log fills with internal `ERROR inference diagnostic in
desugared expr` lines while editing this codebase, a message tied to its
handling of diagnostics inside desugared (`.await`, `?`, `for`,
`tokio::select!`) expressions — but that's a correlation, not a
confirmed cause, and no matching upstream issue has been found. Treat
these squiggles as cosmetic; if one blocks your workflow, trust
`cargo check`/`cargo build` over the editor. If this becomes disruptive
enough to chase further, the next step is a minimal reproduction (a
fresh `cargo new` project, adding dependencies until the phantom errors
reappear, then stripping down) filed at
[rust-lang/rust-analyzer/issues](https://github.com/rust-lang/rust-analyzer/issues).

---

## License

MIT — see [LICENSE](LICENSE).
