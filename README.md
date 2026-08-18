# auditmcp

A local-first audit logging proxy for MCP (Model Context Protocol) tool calls.

auditmcp sits transparently between an MCP client (Claude Code, Claude
Desktop, Cursor, …) and an MCP server. It forwards JSON-RPC traffic
byte-for-byte in both directions while logging every `tools/call` to a local
SQLite database with a tamper-evident SHA-256 hash chain, redacting likely
secrets *before* they are ever written to disk. Everything stays on your
machine: no telemetry, no accounts, no network calls, no cloud dependency.

It is deliberately not an enterprise MCP gateway. There is no Kubernetes, no
OAuth, no multi-tenancy — it is one binary and one config file.

The design contract is **fail-open**: the proxy must never become a blocking
dependency of the agent it is auditing. If logging fails, the tool call still
goes through.

---

## How do I run it?

You need the [Rust toolchain](https://rustup.rs/) (stable) to build, and
Python 3 only if you want to exercise the bundled fake MCP server.

```bash
git clone <this repo>
cd auditmcp
cargo build --release
```

The binary lands at `target/release/auditmcp` (`auditmcp.exe` on Windows).

Copy the example config and point it at your MCP server:

```bash
cp config.example.toml config.toml
```

Then run the proxy, the target server command coming either from the config's
`[target].command` or from trailing args after `--` (trailing args win):

```bash
# Target from config.toml
auditmcp run --config config.toml

# Or override it explicitly
auditmcp run --config config.toml -- python test-fixtures/fake_server.py
```

To put it in front of a real client, wrap the server command in your client's
MCP config. A Claude Code `.mcp.json` entry looks like:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/absolute/path/to/auditmcp",
      "args": ["run", "--config", "/absolute/path/to/config.toml",
               "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

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
auditmcp query  --config config.toml                    # table of tool calls
auditmcp query  --config config.toml --verbose          # + what was redacted and why
auditmcp query  --config config.toml --tool delete_file --since 2h --status error
auditmcp verify --config config.toml                    # walk the hash chain
auditmcp export --config config.toml --format jsonl --output audit.jsonl
auditmcp unmask --config config.toml <sha256> --note "confirmed false positive"
```

`--since` takes a duration with a required unit: `45s`, `30m`, `2h`, `1d`.

### Diagnostics

Warnings go to stderr and are on by default, because the things auditmcp
warns about are the ways your record can be incomplete — an entry dropped
under load, the redactions index drifting, a pipe error. Set `RUST_LOG` to
change it:

```bash
RUST_LOG=error auditmcp run --config config.toml    # quieter
RUST_LOG=debug auditmcp run --config config.toml    # louder
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
| Console close | Windows | Compiled, not verified¹ |
| System shutdown | Windows | Compiled, not verified¹ |
| **Windows Service stop** | Windows | **Not covered²** |

¹ These register through the same console-control handler as Ctrl-Break,
which is verified. They are not separately testable without closing a
console or shutting the machine down, and Windows will not deliver
`CTRL_C_EVENT` to a process group created for testing.

² `SERVICE_CONTROL_STOP` (what `net stop` sends) goes to a service control
handler, not a console event, so none of the above sees it. Running
auditmcp as a true Windows Service needs a service dispatcher, which
belongs with the not-yet-built install/lifecycle work. Until then, stopping
it that way can lose whatever is still queued.

Two conditions refuse to start rather than warn, because both would mean
proxying traffic while silently failing at the job: a database that cannot
be opened (nothing would be recorded, and that fact cannot be recorded
either), and a bundled pattern set that fails to load (every secret would
be stored in the clear). The second indicates a defective build rather than
a configuration problem — the pattern set is compiled into the binary.

### Exit codes

`verify` has two distinct nonzero codes so a monitoring script can tell
tampering apart from an internal index going stale, without parsing output:

| Code | Meaning |
|---|---|
| 0 | Chain intact and redactions index consistent |
| 1 | Hash-chain verification failed — a row was altered, deleted, or reordered |
| 2 | Chain intact, but the derived redactions index drifted (fix with `--repair-index [--yes]`) |

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

**Platforms.** Windows and Linux are both actively tested (see Current
state). macOS should work without special-casing and is covered by CI, but
has never been manually exercised. Released Windows binaries will be
unsigned initially, so SmartScreen may warn on first run.

---

## What state is it in?

Phases 1 and 2 are complete. Phases 3 and 4 are unstarted.

### Working

- **stdio proxy** — spawns the target MCP server, pipes stdin/stdout
  transparently, intercepts `tools/call` request/response pairs. Non-tool
  traffic (`initialize`, `tools/list`, notifications) is forwarded but not
  logged, since this tool audits *tool calls*. Child stderr is inherited so
  tracebacks still reach your terminal.
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

### Not yet built

- **A user-updatable patterns file** — see above.
- **Phase 3 — anomaly detection.** The `anomaly_score` / `anomaly_reasons`
  columns exist in the schema and are always `NULL`; they were added on day
  one specifically to avoid a migration later. `query --anomalous` and
  `watch` do not exist.
- **A user-updatable patterns file.** The spec calls for one; `patterns.toml`
  is currently compiled into the binary with `include_str!` and there is no
  config key pointing at a user copy. Editing `patterns.toml` and rebuilding
  works; editing it next to an installed binary does nothing. This is also
  what makes refusing to start on a pattern-load failure correct — that
  failure can only mean a broken build today, not a user's typo.
- **Phase 4 — Lua policy layer.** No `mlua` dependency yet, by design.

The non-JSON payload path — `truncate::truncate_raw_sampled` and
`secrets::scan_and_redact_text` — handles HTTP response bodies that aren't
JSON (an upstream 502 HTML page, a stack trace, an unexpected content
type). Stdio MCP is JSON-RPC end to end so it never exercises this path;
`serve` does, whenever the upstream returns non-JSON.

### How it has been verified

`cargo test` runs 168 tests covering the hash chain (including concurrent
writers against a shared DB and interleaved multi-server chains), secrets
detection and its false-positive cases, truncation UTF-8 boundary safety,
export fidelity, unmask hash resolution, `verify` exit codes and
`--repair-index` semantics, and the HTTP transport — SSE parser
resynchronization after an oversized event, per-listener id isolation so
two upstreams reusing the same JSON-RPC ids never cross-attribute,
`Host`-header rewriting to the upstream authority, and non-JSON upstream
responses being logged as errors with their body.

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

**`verify` cannot detect deletion of the most recent row(s).** Hash chaining
proves that every row from the beginning up to some point is unaltered and in
its original order, but it can only do that by having a *later* row whose
`id`/`prev_hash` fails to line up with what was deleted. If the tail of the
chain is truncated (the newest N rows removed) there is no later row left to
expose the gap — `verify` will report the chain as fully intact, and this
stays true forever, even after new rows are appended in a future session (the
writer just chains onto whatever the current last row happens to be; it has
no way to know rows used to exist after it).

This is an inherent limit of hash-chaining alone, not a bug — it is the same
reason real append-only transparency logs need an external
checkpoint/witness mechanism, which is out of scope for a local single-user
tool. In short: `auditmcp verify` proves nothing in the middle of the log was
altered or removed, not that nothing was truncated off the end.

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

## Threat model

Primary concern: a prompt-injected or otherwise compromised agent using MCP
tool calls to exfiltrate data or take unintended destructive actions.
Secondary: general accountability — "what did my agent actually do."

Not defended against: a fully malicious MCP client that bypasses the proxy
entirely, or nation-state-level adversaries. This is a practical safety net,
not a hardened boundary.

---

## License

MIT — see [LICENSE](LICENSE).
