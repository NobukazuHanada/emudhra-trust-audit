# Changelog

## 0.2.0 — Rust migration (not yet tagged)

- Replace the Python product, build and test configuration with a Rust CLI using
  stable Rust 1.99.1. Release executables need no Python or Rust installation.
- Embed the reviewed indicator data, retaining external data overrides and
  deterministic LF-normalized SHA-256 verification.
- Preserve endpoint/project audits, evidence/status/confidence/remediation,
  JSON/text/SARIF and exit codes 0–3. Preserve partial dependency parsers,
  SPKI/JKS inspection, explicit executable probes and disclosed coverage gaps.
- Strengthen default privacy with opaque file references, bound subprocess output
  while collecting it, and reject Windows reparse points in project reads.
- Replace Python skill helpers with argument-preserving POSIX/PowerShell wrappers.
- Add five-platform release packaging, archive checksums, third-party license
  collection and cargo-deny CI. Manual builds do not publish a release.
- Deliberate compatibility changes: no execution of Python/certifi environments;
  inspect explicit bundles and lockfiles instead. Prerelease/non-numeric generic
  versions remain unknown. Network probes use one installed OpenSSL invocation
  and never establish other clients' trust. The old Python module and data-env
  override are removed; use --data-dir. Existing .ca-trust-audit-ignore files work.

## 0.1.0 — Historical implementation

Introduced the two audit skills, static rules and version policies, independent
security fixes, cross-platform newline correction and English/Japanese READMEs.
Renamed the public repository to emudhra-trust-audit. Historical implementation
and validation are retained in Git history; they are not proof of Rust behavior.
