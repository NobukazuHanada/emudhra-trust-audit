# Changelog

## 0.3.0 — Skills-only plugin (2026-10-23)

- Rebuild the project as two self-contained agent skills,
  `endpoint-trust-audit` and `project-trust-audit`, packaged as one plugin
  with Claude Code (`.claude-plugin/`) and Codex (`.codex-plugin/`)
  manifests and repository marketplaces for both.
- Users need no Python, Node.js, Rust, package or binary. Audits use fixed,
  read-only OS-standard command blocks: `awk`/`openssl` SPKI hashing on Linux
  and macOS, and built-in PowerShell on Windows (P-384 SPKI reconstruction).
- Keep the four statuses, evidence, confidence, coverage gaps, conditional
  credential guidance and "not detected is not safe". Indicator, policy and
  rule data now live in each skill's `references/` with sources, dates and
  versions. TLS rules are ported to POSIX ERE (data version 2026.10.23) with
  a corrected `curl -k` pattern.
- Deliberate differences from the Rust CLI: no SARIF/JSON output files, exit
  codes or `--output`; no opt-in executable probes of non-OS tools (`node`,
  `go`, `pip`, `claude`), no network test and no `--bundle` argument, so those
  areas are reported as `unable_to_assess`; no opaque file hashes (relative
  paths are shown, with masking rules); `.ca-trust-audit-ignore` is no longer
  read.
- Remove the Rust sources, Cargo files, tests, release workflow and packaging
  script from `main`. The Rust CLI is preserved on `archive/rust-cli`
  (`3233891a5578630200f95ccbd74577553e2b4845`).
- Replace Rust CI with a lightweight validation workflow.

## 0.2.0 — Rust CLI (never tagged; archived)

Standalone Rust CLI with embedded indicator data and POSIX/PowerShell skill
wrappers. Preserved on the `archive/rust-cli` branch.

## 0.1.0 — Historical implementation

Introduced the two audit skills, static rules and version policies and
English/Japanese READMEs. Retained in Git history.
