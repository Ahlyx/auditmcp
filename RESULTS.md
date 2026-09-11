# auditmcp closeout results

## Question

Can a single developer put one local binary in front of MCP servers and get a
useful, tamper-evident account of tool calls without running an enterprise
gateway or maintaining a policy configuration?

## Result

Yes, within the threat model documented in the README. Version 0.1.0 is a
feature-complete local audit proxy for stdio, Streamable HTTP, and legacy
HTTP+SSE MCP transports. It forwards traffic, correlates `tools/call`
requests with their outcomes, redacts likely credentials before persistence,
scores three explainable anomaly signals, and writes the result to SQLite.
The log uses an HMAC hash chain, randomized heartbeats, and an external HMAC
anchor. `auditmcp verify` distinguishes tampering, derived-index drift,
heartbeat gaps, anchor failures, and durable markers proving that fail-open
logging dropped entries.

The end-user path is intentionally small: download one portable archive and
run `auditmcp run -- <server command>`. No config, account, service, external
database, or network dependency is required. Configuration remains available
for shared databases, reusable commands, logging tiers, and HTTP upstreams.

## Evidence at closeout

- 285 Rust tests pass locally, including concurrent writers, redaction and
  false-positive cases, hash/HMAC verification, HTTP stream behavior,
  anomaly rules, shutdown draining, and reset/repair behavior.
- `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D
  warnings`, and the optimized release build pass.
- A packaged Windows binary completed a configless end-to-end smoke test:
  proxy the fake MCP server, record and redact a test key, query the row, and
  verify the resulting chain.
- CI is configured to repeat formatting, tests, and linting on Windows,
  Linux, and macOS; run RustSec auditing; and build and smoke-test release
  archives for Windows x64, static Linux x64, macOS Intel, and macOS Apple
  silicon.

The branch/PR CI run is the remaining independent confirmation before the
first release tag. This file does not claim that pending run has passed.

## Produced artifacts

Runtime state is stored under the current user's platform state directory;
`auditmcp key path` prints the key path and `auditmcp query` reads the default
database. Tagged releases produce:

- `auditmcp-x86_64-pc-windows-msvc.zip`
- `auditmcp-x86_64-unknown-linux-musl.tar.gz`
- `auditmcp-x86_64-apple-darwin.tar.gz`
- `auditmcp-aarch64-apple-darwin.tar.gz`
- `SHA256SUMS` plus GitHub artifact attestations

## Caveats and stopping point

auditmcp is fail-open: the tool call continues if logging fails, with a
warning and a durable gap marker when persistence recovers. It cannot audit a
client that bypasses it, and full-machine compromise can expose the chain
key. Transparent interactive OAuth proxying is not supported. Corporate TLS
inspection roots are not read from the system store. macOS is CI-covered but
has not been manually exercised, and Windows releases are not code-signed.

The Lua policy gateway, live `watch` UI, runtime-custom pattern files, and
service installers are deliberate scope cuts, not unfinished placeholders.
The project stops at a local audit tool. Resume feature development only in
response to a concrete user need; otherwise maintain security, dependencies,
MCP compatibility, and confirmed bugs.
