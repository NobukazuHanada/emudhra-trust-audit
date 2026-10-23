# endpoint-trust-audit plugin

**Unofficial and independent. Not affiliated with or endorsed by eMudhra.**

One read-only skill for Claude Code and Codex that checks whether this
computer is exposed to the 2026 eMudhra weak intermediate CA key incident. It
needs no extra runtime, package or binary: the agent runs fixed, read-only
OS-standard commands on macOS, Linux or Windows.

It hashes certificates in system CA bundles, OS trust stores, keychains and
CA override files against the eight compromised SPKI SHA-256 values, and
checks the OS CA package version and TLS-disabling settings. To audit a
repository instead, install the companion `project-trust-audit` plugin.

Results are `known_indicator`, `suspicious`, `not_found` or
`unable_to_assess`, each with evidence, confidence and advice. "Not detected"
does not mean safe. The skill never installs, changes, deletes, elevates or
sends data.

Full documentation, install commands, privacy notes and limitations:
https://github.com/NobukazuHanada/emudhra-trust-audit

License: Apache-2.0 (see `LICENSE` and `NOTICE`).
