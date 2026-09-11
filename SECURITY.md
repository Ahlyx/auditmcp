# Security policy

## Supported version

Security fixes are applied to the latest release. This is a small,
maintainer-driven project and older release lines are not supported.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting form for this repository:

<https://github.com/Ahlyx/auditmcp/security/advisories/new>

If that form is unavailable, open a GitHub issue asking for a private contact
channel, but do not include exploit details, credentials, private audit rows,
or other sensitive data in the issue. Ordinary non-sensitive bugs can be
reported directly through GitHub Issues.

Include the affected auditmcp version and platform, the smallest reproduction
you can provide safely, the security impact, and whether you believe any real
credential was written or exposed. Never send a live credential; revoke it
first and use a synthetic replacement in the report.

## Scope and expectations

High-priority reports include plaintext secret persistence despite a bundled
detector match, hash/HMAC or anchor verification bypasses, escaping the
loopback-only HTTP boundary, unexpected capture of authorization headers, and
traffic corruption by the transparent proxy.

The documented threat model still applies. auditmcp is fail-open and is not a
policy enforcement boundary. It does not protect against a client that routes
around it, an attacker with full access to both the database and key, or
secrets whose format is not recognized by the bundled detectors.
