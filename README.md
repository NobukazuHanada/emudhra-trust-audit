[English](README.md) | [日本語](README.ja.md)

# emudhra-trust-audit

**Unofficial and independent. Not affiliated with, endorsed by or operated by eMudhra, Anthropic or OpenAI.**

Two read-only agent skills for Claude Code and Codex that check exposure to the
2026 [eMudhra weak intermediate CA key incident](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).
They are plain instructions and data (`SKILL.md` plus Markdown references).
**Installing them needs no Python, Node.js, Rust, package or downloaded binary.**
The agent runs fixed, read-only commands that ship with the operating system.

- **endpoint-trust-audit**: this computer. Hashes certificates in system CA
  bundles, OS trust stores, keychains and CA override files and compares them
  with the eight compromised SPKI SHA-256 values; checks the OS CA package
  version and TLS-disabling settings.
- **project-trust-audit**: a repository. Hashes vendored CA bundles, finds TLS
  verification bypasses and custom CA overrides in code, configuration,
  containers and CI, and compares lockfile and tool-pin versions with fixed
  versions. Never runs project code.

This is not a malware scanner. **"Not detected" does not mean safe.**

## Install

There are two plugins, one skill each. Install only the one you need, or
both; each works on its own.

### Claude Code

```sh
claude plugin install endpoint-trust-audit --marketplace NobukazuHanada/emudhra-trust-audit
claude plugin install project-trust-audit --marketplace NobukazuHanada/emudhra-trust-audit
```

Each line adds this repository as the marketplace `emudhra-trust-audit` if
needed and installs one plugin. If your Claude Code does not accept
`--marketplace`, add the marketplace first:

```sh
claude plugin marketplace add NobukazuHanada/emudhra-trust-audit
claude plugin install endpoint-trust-audit@emudhra-trust-audit
claude plugin install project-trust-audit@emudhra-trust-audit
```

### Codex

```sh
codex plugin marketplace add NobukazuHanada/emudhra-trust-audit
codex plugin add endpoint-trust-audit@emudhra-trust-audit
codex plugin add project-trust-audit@emudhra-trust-audit
```

### Without a plugin system

Download this repository (GitHub **Code → Download ZIP**) and copy the skill
folder you need into your personal skills directory, `~/.claude/skills/` for
Claude Code or `~/.agents/skills/` for Codex:

- `plugins/endpoint-trust-audit/skills/endpoint-trust-audit/`
- `plugins/project-trust-audit/skills/project-trust-audit/`

Each folder is self-contained.

### Upgrading from 0.3.0

Version 0.3.0 shipped both skills as one plugin named `emudhra-trust-audit`.
Remove it before installing the new plugins:
`claude plugin uninstall emudhra-trust-audit@emudhra-trust-audit` or
`codex plugin remove emudhra-trust-audit@emudhra-trust-audit`.

## Update

| Tool | Commands |
| --- | --- |
| Claude Code | `claude plugin marketplace update emudhra-trust-audit`, then `claude plugin update endpoint-trust-audit@emudhra-trust-audit` and/or `claude plugin update project-trust-audit@emudhra-trust-audit` (restart the session) |
| Codex | `codex plugin marketplace upgrade emudhra-trust-audit`, then `codex plugin add endpoint-trust-audit@emudhra-trust-audit` and/or `codex plugin add project-trust-audit@emudhra-trust-audit` |
| Manual copy | Replace the copied folder |

## Uninstall

| Tool | Commands |
| --- | --- |
| Claude Code | `claude plugin uninstall endpoint-trust-audit@emudhra-trust-audit` and/or `claude plugin uninstall project-trust-audit@emudhra-trust-audit`, then `claude plugin marketplace remove emudhra-trust-audit` |
| Codex | `codex plugin remove endpoint-trust-audit@emudhra-trust-audit` and/or `codex plugin remove project-trust-audit@emudhra-trust-audit`, then `codex plugin marketplace remove emudhra-trust-audit` |
| Manual copy | Delete the copied folder |

## Use

Ask in plain language, for example "Does this computer still trust the
compromised eMudhra CA keys?" or "Audit this repository for the eMudhra CA
incident."

- Claude Code: the skills load automatically when relevant, or call them
  directly with `/endpoint-trust-audit:endpoint-trust-audit` and
  `/project-trust-audit:project-trust-audit` (`/endpoint-trust-audit` and
  `/project-trust-audit` after a manual copy).
- Codex: the skills load automatically when relevant; you can also name
  `endpoint-trust-audit` or `project-trust-audit` in the request.

For a project audit, start the agent in the repository root. Claude Code and
Codex ask for approval before running commands, according to your permission
settings; review each command.

## Permissions

The agent runs only the command blocks in each skill's `references/` catalogue,
verbatim:

- Linux/macOS: `sh`, `awk`, `find`, `grep`, `cat`, `openssl`, `uname`,
  `printenv`, and where present `security` (macOS), `dpkg-query`, `rpm`,
  `pacman` or `apk`, with `PATH` fixed to OS directories.
- Windows: built-in Windows PowerShell 5.1 or PowerShell 7, reading
  `Cert:\` stores, a few files, environment variables and two registry values.

The skills forbid installing, changing, deleting, elevating (`sudo`, run as
administrator), executing project code, running programs outside the OS
(such as `node` or `python`) and network access. Commands do not embed
untrusted values: file contents are passed on standard input and file names
only through `find`. On Windows, CA files named by environment variables are
opened only on local drives, so the audit never contacts a file server. Each
block runs once with a 120-second timeout and prints bounded summaries. These are instructions to the agent, not a sandbox:
your agent's own permission prompts remain the enforcement point.

## Privacy

The skills send nothing anywhere themselves. The agent does read command
output, and that output is processed by the AI service you use (Anthropic or
OpenAI) under its terms. To keep that small, the commands print only labels,
counts, hashes, versions, matched setting fragments and, for lockfiles, the
few truncated lines that hold a version, never whole files. Credentials in
URLs are replaced with `<redacted>` before output. The report rules mask home
paths, user names, secrets and certificate subjects. See [PRIVACY.md](PRIVACY.md).

## Results

Each check is one of:

| Status | Meaning |
| --- | --- |
| `known_indicator` | Exact match: compromised SPKI, TLS-disabling setting, or version below the fixed version |
| `suspicious` | Needs human confirmation |
| `not_found` | The check completed and found nothing (only for that check) |
| `unable_to_assess` | Could not be checked; never a pass |

Every finding includes evidence, confidence, location, what you can do, and
the data source. The verdict is ACTION REQUIRED, REVIEW REQUIRED, or NO
ACTION IDENTIFIED IN COMPLETED CHECKS. Credential advice depends on evidence;
the skills never order blanket rotation and never declare it unnecessary.

## Limitations

- What cannot be checked with OS-standard commands is reported as
  `unable_to_assess`: browser and NSS stores, Java keystores, runtimes with
  built-in roots (Node.js, Go, Electron, Deno), effective chain acceptance,
  revocation freshness, and whether an interception ever happened.
- On Windows, only P-384 keys are hashed. All eight indicators are P-384, so
  other key types cannot match.
- Presence of a compromised SPKI does not prove a client accepts it.
- Text rules can miss obfuscated settings or match harmless text.
- Containers and WSL describe only themselves, not their host.
- Indicator data is a dated snapshot (facts as of 2026-10-21, data version
  2026.10.22). The skills never fetch updates.

## Data and sources

Each skill carries `references/indicators.md`, `fixed-versions.md` and (for
projects) `tls-rules.md`, with source URLs, retrieval dates and data
versions. Sources are Mozilla, Google, eMudhra, Cloudflare, CISA and a
community tracker; see [NOTICE](NOTICE).

## Marketplace status

- This repository is itself a plugin marketplace for Claude Code
  (`.claude-plugin/marketplace.json`) and Codex
  (`.agents/plugins/marketplace.json`). The install commands above use it.
- It has **not** been submitted to the Anthropic plugin directory or the
  OpenAI plugin directory. Both require submission and review by the
  respective company, and acceptance is not guaranteed. The plugin names do
  not contain a third-party brand, but descriptions and the marketplace name
  mention eMudhra to identify the incident; both directories review brand
  use.

## Rust CLI (archived)

The previous standalone Rust command-line tool is preserved, unchanged, on the
[`archive/rust-cli`](https://github.com/NobukazuHanada/emudhra-trust-audit/tree/archive/rust-cli)
branch (commit `3233891a5578630200f95ccbd74577553e2b4845`). It is no longer
maintained on `main`, and no binary release was published.

## Repository layout

```text
.claude-plugin/marketplace.json      Claude Code marketplace
.agents/plugins/marketplace.json     Codex marketplace
plugins/endpoint-trust-audit/        plugin 1 (same layout for plugin 2)
  .claude-plugin/plugin.json         Claude Code manifest
  .codex-plugin/plugin.json          Codex manifest
  skills/endpoint-trust-audit/       SKILL.md + references/
plugins/project-trust-audit/         plugin 2
  skills/project-trust-audit/        SKILL.md + references/
scripts/validate.sh                  CI checks (maintainers only)
```

## Contributing, security and license

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CHANGELOG.md](CHANGELOG.md). Licensed under [Apache-2.0](LICENSE).
"eMudhra" and "emSign" are marks of eMudhra Limited, used only to identify the
affected certificate authority.
