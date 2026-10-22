[English](README.md) | [日本語](README.ja.md)

# emudhra-trust-audit

**An unofficial, independent community project. This is not an eMudhra tool and is not affiliated with or endorsed by eMudhra.**

A local, read-only audit tool and two independent Agent Skills for the [eMudhra intermediate CA key compromise](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449). This is not a malware scanner.

- **endpoint-trust-audit** inspects CA stores, CA override environment variables, TLS settings, runtimes and developer CLIs on macOS, Linux and Windows.
- **project-trust-audit** statically inspects a project's dependencies, lockfiles, CA bundles, build and development tools, containers, CI and TLS settings.

Requires Python 3.9 or later, with no runtime dependencies beyond the standard library. By default, audits execute no external commands, make no network connections and write no files. There is no automatic remediation. This is an early release: **“not detected” does not mean “safe.”**

## Supported environments

Targets macOS, Linux and Windows with Python 3.9 or later. Python 3.9 remains a legacy compatibility target; this project does not provide maintenance or security updates for Python itself. Use a maintained Python release for new installations. CI covers Python 3.9, 3.12 and 3.14 on Ubuntu 22.04, macOS latest and Windows latest. Linux is pinned to 22.04 because Ubuntu latest moved to 26.04, where setup-python could not obtain Python 3.9. This does not establish support for every OS release or every Python minor version. Mocked store tests in CI do not replace validation of all clients on a real endpoint.

## Quick start

Clone the source and run from its root. On Windows, replace `python3 -B` with `py -3 -B`. Quote paths containing spaces.

```sh
git clone https://github.com/NobukazuHanada/emudhra-trust-audit.git
cd emudhra-trust-audit
python3 -B bin/emudhra-trust-audit.py endpoint --format json
python3 -B bin/emudhra-trust-audit.py project /path/to/project --format json
python3 -B bin/emudhra-trust-audit.py data --verify
python3 -B bin/emudhra-trust-audit.py explain ENDPOINT-SPKI-TRUSTED
```

OS-store and version checks that require executable probes are reported as unable to assess by default. Use `endpoint --commands` only to inspect trusted installed tools. Do not use it if executable lookup through PATH, Python startup hooks or Node environment settings are untrusted. `--no-commands` takes precedence over `--commands`.

Use `--bundle PATH` for an additional endpoint bundle or `--scan-bundle FILE` for a project bundle. Reports go to stdout unless you explicitly request `--output FILE`. Optional `--network-test HOST` requires consent to disclose your IP address and other connection information to the destination. Certificates and handshake results obtained over separate connections are not combined into a claim of safety or exposure.

To install the CLI, run `python -m pip install .` in a dedicated virtual environment, then check `emudhra-trust-audit --help`. No package has been published to PyPI. Building may require downloading build dependencies.

## Install in Claude Code or Codex

The root `skills/` directory is for development. Build portable skills to bundle the shared implementation, indicator data and licenses into each skill:

```sh
python3 scripts/build_skills.py dist/skills
```

An existing destination is not overwritten. Copy either or both generated folders, in full, to the appropriate location. Each works independently of the other skill and the original checkout.

| Host | Personal | Project |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.agents/skills/` | `.agents/skills/` |

On Windows, `~` means your user profile directory. You can copy the folders in File Explorer; no symlinks or administrator privileges are required. Restart the session to ensure discovery. Locations follow the [Claude Code documentation](https://code.claude.com/docs/en/skills) and [Codex documentation](https://learn.chatgpt.com/docs/build-skills).

In Claude Code, invoke `/endpoint-trust-audit` or `/project-trust-audit`. In Codex, invoke `$endpoint-trust-audit` or `$project-trust-audit`. For example, ask “Audit this machine offline” or “Audit the current project without changing it.”

A skill's helper can also run from any working directory:

```sh
python3 -B /absolute/path/endpoint-trust-audit/run.py endpoint --format json
python3 -B /absolute/path/project-trust-audit/run.py project . --format json
```

## Results and exit codes

JSON contains `schema_version`, `verdict`, `action`, `exit_code`, `findings`, `data_sources`, `notes` and `errors`. Findings include evidence, confidence, sources and remediation. Text and SARIF output are available with `--format text` and `--format sarif`.

| Status | Meaning |
| --- | --- |
| `known_indicator` | Observed a match against indicator data or rules |
| `suspicious` | A text or pattern match whose actual use requires review |
| `not_found` | Not found within checks that completed |
| `unable_to_assess` | Unsupported input, read failure, insufficient evidence or another coverage gap |

| Exit code | Meaning |
| --- | --- |
| 0 | No further action identified by completed checks; not a safety guarantee |
| 1 | Review required, including unresolved coverage gaps |
| 2 | Action required |
| 3 | Data integrity, input or execution error |

`UNKNOWN` can coexist with `action_required`. A stored key warrants remediation review but does not prove that a running client accepts it. `EXPOSED` and `BLOCKED` are reserved for effective acceptance or rejection; current store and version checks do not establish either. `INSECURE` means findings include disabled TLS verification; inspect their status and confidence.

## Coverage and limitations

- Implements known OS paths and opt-in keychain, Windows-store, runtime and package queries. Default macOS and Windows checks are limited to files.
- Includes partial parsers for npm, Yarn, pnpm, requirements, Poetry, uv, Pipenv, PDM, Cargo, Go, Composer, Bundler and Hex. Binary Bun locks, NuGet and Gradle are inventory-only and reported as unable to assess. Not every format, syntax or transitive dependency is resolved.
- Compares known CA-related packages. It is not general software composition analysis covering all CVEs, modified packages or malicious dependencies.
- Defaults to 20,000 files and 1 MiB per project file. Symlinks, special files, oversized files, installed dependency directories and build outputs are excluded. Exclusions from `.ca-trust-audit-ignore` are recorded in the report.
- Does not enter containers, fetch images, resolve packages or execute project scripts. Results inside WSL or a container describe that environment only.
- A server may supply a trusted chain even if its intermediate is absent locally. The presence or removal of related roots alone does not establish safety.
- Revocation freshness, running-process caches, browser-specific policies, effective Schannel/Authenticode validation and Java PKCS#12 are unverified or unsupported.
- Local validation runs on Linux. Mocked macOS/Windows responses and a CI matrix are provided; real-device validation is still needed.

## Remediation

Update the OS, browsers, CA packages and runtimes through official channels, then restart affected processes. Update custom bundles, virtual environments, CI images and containers; rebuild, redeploy and audit again. Never disable TLS verification as a workaround or indiscriminately delete root certificates.

Scope credential rotation using evidence of actual connections, authentication and modification. Neither “rotate everything” nor “rotation is unnecessary” is a blanket conclusion. The scanner changes neither credentials nor trust settings.

## Privacy and threat model

The scanner sends nothing externally by default. It omits source lines, tokens, proxy URLs and private-key contents from reports and redacts usernames and home paths. Reports still include relative filenames, public package names and versions; review them before sharing. Unknown secrets embedded in arbitrary filenames cannot be reliably recognized.

**Sharing output with online Claude or Codex is separate from the scanner's own networking.** If everything must stay on your machine, run the CLI directly and do not share output with an external service. Do not ask an assistant to paste raw configuration files into the conversation. Audit a stable snapshot of untrusted directories.

## Development and tests

Run the following in a development virtual environment. On Windows, replace `python3` with `py -3`.

```sh
python3 -m pip install pytest ruff build
python3 -m pytest
python3 -m ruff check .
python3 -m ruff format --check .
python3 -B bin/emudhra-trust-audit.py data --verify
python3 scripts/build_skills.py dist/skills
python3 -m build
```

Choose a new, empty output directory if the build destination already exists. Tests cover LF, CRLF and CR data, tampering after newline conversion, and standalone skills outside the checkout. When editing skills, run the `quick_validate.py` helper supplied by `skill-creator` against both skill folders. That optional validation tool is not bundled here.

## Data, contribution and license

Indicators, rules and fixed-version policies live in `data/`, with source URLs, dates, versions and SHA-256 digests. Updates are reviewed commits, never runtime downloads. JSON digests normalize CRLF and CR to LF while detecting other byte changes. `.gitattributes` also keeps checkouts at LF. Checksums provide consistency checks, not signatures or proof of source authenticity. Much of the version policy is a 2026-10-21 snapshot from the [community tracker](https://emudhra.we-have-a-problem.com/); maintainers should recheck primary vendor notices when updating it.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md). Licensed under Apache-2.0; [LICENSE](LICENSE) and [NOTICE](NOTICE) are included. This project is not affiliated with or endorsed by eMudhra, Anthropic, OpenAI or GitHub. It does not bundle third-party repair scripts or compromised certificates. Test certificates are synthetic fixtures.

## Independent audit (2026-10-22)

[AUDIT.md](AUDIT.md) records the independent review, corrections, validation and remaining risks. Project symlinks are rejected again immediately before reading. Endpoint certificates and keystores use bounded regular-file reads; OS certificate symlinks are followed because legitimate stores use them. Default limits are 1 MiB for project files and normally 16 MiB for endpoint bundles (32 MiB in the certificate-file API).

`--commands` does not isolate processes or guarantee that startup hooks and installed tools will not communicate or write files. For offline operation, use the default mode with a stable local snapshot. Reading network mounts can trigger OS-level traffic. Concurrent replacement of parent directories is not prevented atomically on every OS.

The scanner compares `.nvmrc`, `.node-version`, `.go-version`, `.tool-versions` and simple mise `[tools]` pins. Unparsed manifests are coverage gaps. Comments, conditional settings, test fixtures and complex TOML exceed static pattern matching's guarantees; review findings in context.

## Renaming and compatibility

The product, GitHub repository, distribution and CLI are named `emudhra-trust-audit`. The checkout entrypoint is now `bin/emudhra-trust-audit.py`; update existing caller scripts. For compatibility, the Python module `ca_trust_audit`, data override variable `CA_TRUST_AUDIT_DATA_DIR` and exclusion file `.ca-trust-audit-ignore` are retained. The two skill names are unchanged. Historical audit records and synthetic certificate subjects retain the original name.
