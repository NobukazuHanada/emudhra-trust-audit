# emudhra-trust-audit plugin

**Unofficial and independent. Not affiliated with or endorsed by eMudhra.**

Two read-only skills for Claude Code and Codex that check exposure to the
2026 eMudhra weak intermediate CA key incident. They need no extra runtime,
package or binary: the agent runs fixed, read-only OS-standard commands.

- `endpoint-trust-audit`: hashes certificates in this computer's CA bundles,
  trust stores and keychains against the eight compromised SPKI SHA-256
  values, and checks CA package versions and TLS-disabling settings.
- `project-trust-audit`: hashes a repository's vendored CA bundles, finds TLS
  verification bypasses and CA overrides, and compares lockfile versions with
  fixed versions, without running project code.

Results are `known_indicator`, `suspicious`, `not_found` or
`unable_to_assess`, each with evidence, confidence and advice. "Not detected"
does not mean safe. The skills never install, change, delete, elevate or send
data.

Full documentation, install commands, privacy notes and limitations:
https://github.com/NobukazuHanada/emudhra-trust-audit

License: Apache-2.0 (see `LICENSE` and `NOTICE`).
