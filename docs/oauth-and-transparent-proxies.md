# OAuth-protected MCP servers cannot be transparently proxied

**Status:** measured 2026-08-10 against `@modelcontextprotocol/sdk` 1.30.0.
This is a property of MCP's authorization model, not a defect in auditmcp
or in any client. If you are building a local MCP proxy, interceptor, or
gateway, you will hit this; it took a day to establish and the mechanism is
one line of SDK code.

## The finding

A client pointed at a local proxy in front of an OAuth-protected MCP server
**fails during authorization discovery, before any token is requested.**
Both clients tested report:

```
Protected resource https://upstream.example/mcp does not match
expected http://127.0.0.1:8787/mcp (or origin)
```

No token is issued, no request is made to the authorization server, and
nothing reaches the audit log — the session never starts.

## Why this is nobody's bug

A local proxy makes the client's URL and the resource's canonical identity
disagree **by construction**. That is what transparent interposition means
in a protocol that binds tokens to identities.

And from the client's side there is no way to tell the difference:

> **A transparent proxy and a metadata-spoofing attacker are
> indistinguishable to an MCP client.** Both present a server whose
> advertised canonical identity differs from the URL the client was told to
> trust. The check exists to stop the attack; it cannot tell the two apart,
> because there is nothing to tell apart. Neither side is wrong.

Whether a given client works is therefore a question of how strictly it
validates — a compatibility question, not a bug report.

## The mechanism

MCP requires a server to publish RFC 9728 protected resource metadata whose
`resource` field is its canonical URI, and requires clients to send that
identity as the RFC 8707 `resource` parameter so the issued token is bound
to it. The server then MUST reject tokens not issued for itself.

The SDK enforces the link between "the URL I was given" and "the identity
that URL claims" before it will proceed. In
`@modelcontextprotocol/sdk@1.30.0`:

`dist/esm/client/auth.js`, in `selectResourceURL`:

```js
// Validate that the metadata's resource is compatible with our request
if (!checkResourceAllowed({ requestedResource: defaultResource,
                            configuredResource: resourceMetadata.resource })) {
    throw new Error(`Protected resource ${resourceMetadata.resource} does not ` +
                    `match expected ${defaultResource} (or origin)`);
}
```

`dist/esm/shared/auth-utils.js`, in `checkResourceAllowed`:

```js
// Compare the origin (scheme, domain, and port)
if (requested.origin !== configured.origin) {
    return false;
}
```

**Origin is scheme + host + port.** A loopback proxy differs from its
upstream by port by construction, so the comparison fails before the
path-prefix logic below it ever runs. There is no path layout, no
configuration option, and no cooperation from the upstream that satisfies
it.

## What was tested

A local rig, deliberately spec-shaped:

- **Resource server** on `127.0.0.1:3300` — returns `401` with
  `WWW-Authenticate: Bearer ... resource_metadata="..."`, and serves RFC
  9728 metadata whose `resource` is its own canonical URL, which is what a
  real upstream does.
- **Authorization server** on `127.0.0.1:4400` — advertises
  `code_challenge_methods_supported: ["S256"]` and a
  `registration_endpoint`, logs every parameter it is handed, and approves
  without human interaction.
- **auditmcp** on `127.0.0.1:8787`, mirroring `127.0.0.1:3300`.

### Control

The same client pointed **directly** at `127.0.0.1:3300` completes the flow:
`REDIRECT` → `AUTHORIZED`, with `resource=http://127.0.0.1:3300/mcp` in both
the authorization URL and the token request. The rig is correct and the flow
works. Only interposition fails.

### Client 1 — the official TypeScript SDK (1.30.0)

Fails immediately at discovery. Never contacts the authorization server.

### Client 2 — Claude Code

Fails with the **identical** error. It probes in a different order — an
unauthenticated request first, then follows the absolute `resource_metadata`
URL directly to the upstream, then fetches authorization server metadata —
and then applies the same validation. Different route, same verdict, because
it is built on the same SDK.

*(An earlier reading of the intermediate trace suggested the two clients
disagreed. They do not; only their probing order differs.)*

## Why no choice of provider fixes it

The rejection happens **in the client**, using only the URL it was
configured with and the metadata the server published. The provider's
strictness never comes into it — the token request is never made.

Confirmed against GitHub's remote MCP server as a real-world example
(unauthenticated probes, 2026-08-10):

- `https://api.githubcopilot.com/mcp/` returns a well-formed `401` with an
  absolute `resource_metadata` URL.
- Its metadata declares `resource: "https://api.githubcopilot.com/mcp/"` and
  `authorization_servers: ["https://github.com/login/oauth"]`.
- That origin can never equal a loopback origin, so the same check applies.

GitHub is additionally unreachable for arbitrary clients: its authorization
server metadata has **no `registration_endpoint`**, so Dynamic Client
Registration is unsupported and only pre-registered first-party clients can
authenticate at all. But that is a second, independent obstacle — removing
it would not change the outcome above.

### A related note on scopes

GitHub's `/readonly` endpoint variant has its own `resource` identity but
advertises **the same `scopes_supported` as the read-write endpoint**,
including `repo` — which is full read *and* write. Read-only is enforced as
a tool filter on the server, not as a constraint on the granted token.

This is a limitation of classic OAuth scopes rather than a choice: they have
no read-only repository scope to offer. If you need a token that genuinely
cannot write, use a **fine-grained** personal access token, which can
express read-only repository permissions, rather than relying on a
read-only endpoint or a classic scope.

## What still works

Only the interactive OAuth *discovery* path is affected.

| Server authentication | Through a local proxy |
|---|---|
| None | Works |
| Static header / personal access token | Works — header forwarded untouched, never stored |
| Interactive OAuth, SDK-default validation | **Blocked at discovery** |
| Interactive OAuth, client overriding validation | Would work; no such client known |

A client configured with an explicit `Authorization` header never enters
OAuth discovery, so the origin check never runs.

## The escape hatch, for client authors

The SDK exposes an override:

```ts
validateResourceURL?(serverUrl: string | URL, resource?: string): Promise<URL | undefined>;
```

> If defined, overrides the selection and validation of the RFC 8707
> Resource Indicator. If left undefined, default validation behavior will be
> used.

A client that wants to support local interception can implement it and
accept a resource whose origin differs from the configured URL — accepting,
deliberately, the spoofing risk the default check exists to prevent. No
client is known to do this today, and auditmcp does not ask anyone to.

**What auditmcp will not do:** rewrite the `WWW-Authenticate` challenge or
the resource metadata so the advertised identity names the proxy. That would
make discovery succeed and audience binding meaningless — the token would be
issued for the wrong resource, which is the exact attack RFC 8707 exists to
prevent. A proxy that silently defeats a security control to make itself
work is worse than one that does not work.

## Reproducing

The rig is two small HTTP servers and a client probe; nothing in this
repository depends on it. The essentials:

1. Serve RFC 9728 metadata from an upstream whose `resource` is its own URL.
2. Put any transparent proxy in front of it on a different port.
3. Point an SDK-based client at the proxy.
4. Observe the error above, and observe that the authorization server is
   never contacted.

The control in step 3 — pointing the same client straight at the upstream —
is what distinguishes "interposition is rejected" from "the rig is wrong".
