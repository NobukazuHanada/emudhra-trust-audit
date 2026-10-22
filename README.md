[English](README.md) | [日本語](README.ja.md)

# emudhra-trust-audit

**Unofficial and independent. This project is not affiliated with, endorsed by or operated by eMudhra.**

A Rust command-line auditor for the [eMudhra intermediate CA key incident](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449), with two skills for Claude Code and Codex. The executable includes its indicator data. **Users do not need Python, Rust, Cargo or another language runtime.** This is not a malware scanner, and “not detected” is not proof of safety.

- **endpoint-trust-audit**: inspect this machine's CA bundles, TLS overrides and client configuration; optionally query OS stores and installed tools.
- **project-trust-audit**: inspect a repository's dependencies, lockfiles, CA bundles, tool pins, containers, CI and TLS settings without running project code.

Default audits only read local files. They do not download data, send reports, modify trust stores, install packages or perform remediation. Explicit `--output` creates a new report file and refuses to overwrite an existing file.

## Platforms and distribution

| Platform | Archive target |
| --- | --- |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Linux x86_64 | `x86_64-unknown-linux-musl` |
| Linux arm64 | `aarch64-unknown-linux-musl` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

Linux release builds use musl to avoid a glibc-version dependency. macOS and Windows use their standard OS facilities. CI covers hosted Linux, macOS and Windows; it does not guarantee every historical OS release, enterprise policy or real trust store. Binaries are not currently signed or notarized.

Download the matching archive and `SHA256SUMS` from [GitHub Releases](https://github.com/NobukazuHanada/emudhra-trust-audit/releases). Verify the archive's SHA-256 against its line in the manifest before extracting it. For example:

```sh
# Linux
sha256sum emudhra-trust-audit-x86_64-unknown-linux-musl.tar.gz
# macOS
shasum -a 256 emudhra-trust-audit-aarch64-apple-darwin.tar.gz
```

```powershell
# Windows PowerShell
Get-FileHash .\emudhra-trust-audit-x86_64-pc-windows-msvc.tar.gz -Algorithm SHA256
tar -xf .\emudhra-trust-audit-x86_64-pc-windows-msvc.tar.gz
```

On macOS/Linux use `tar -xzf ARCHIVE.tar.gz`. Run the extracted executable directly, or put it in a trusted directory on PATH. Keep licenses and notices when redistributing it. Never pipe an unreviewed download into a shell. SHA-256 checks integrity against the manifest, not authenticity independently of GitHub.

**The Rust migration does not itself publish a tag or Release.** Until a tagged release is published, use a source build or the `release-assets-with-checksums` artifact from a successful manual [Release artifacts workflow](https://github.com/NobukazuHanada/emudhra-trust-audit/actions/workflows/release.yml). Manual runs build archives only; they do not publish a Release.

## Build from source

Developers need the [Rust toolchain](https://rust-lang.org/tools/install/), not Python. Stable Rust **1.99.1** is pinned in `rust-toolchain.toml` and is the declared minimum supported Rust version (MSRV). Build dependencies are locked in `Cargo.lock`; builds may download them.

```sh
git clone https://github.com/NobukazuHanada/emudhra-trust-audit.git
cd emudhra-trust-audit
cargo build --locked --release
./target/release/emudhra-trust-audit data --verify
```

On Windows run `.\target\release\emudhra-trust-audit.exe`. Only the built executable is required for audits; there is no interpreter, package installation or adjacent data directory requirement. No crates.io package is published as part of this migration.

## Run an audit

```sh
emudhra-trust-audit endpoint --format json
emudhra-trust-audit project /path/to/project --format json
emudhra-trust-audit data --verify
emudhra-trust-audit explain PROJECT-TLS-VERIFY-NODE-ENV
```

On Windows, an executable in the current directory is invoked as `.\emudhra-trust-audit.exe`. Quote paths containing spaces.

- `endpoint --bundle PATH` or `project --scan-bundle FILE`: inspect an additional explicit CA source.
- `endpoint --commands`: opt in to trusted installed executable probes. They use fixed argument vectors, not project-controlled shell strings. Installed tools and startup hooks can nevertheless write, download or send telemetry. `--no-commands` is the default and takes precedence.
- `endpoint --no-user-stores`: omit per-user stores and user client configuration.
- `endpoint --network-test HOST --commands`: explicitly authorize a TLS connection through installed OpenSSL. Discloses source IP and connection metadata. Accepts a hostname or IP on port 443, not a URL or shell expression. A failed connection is not proof of CA rejection; one client/chain does not establish others' behavior.
- `project --no-containers`: omit container-specific checks.
- `--format json|text|sarif`: choose output. `--output NEW_FILE` explicitly saves it.
- `--data-dir DIR`: use a reviewed external data snapshot instead of embedded data. No network update occurs.

No administrator privileges are required. Unavailable stores are reported as coverage gaps.

## Claude Code and Codex skills

Each release archive contains `skills/endpoint-trust-audit/` and `skills/project-trust-audit/`, each with its own binary and license notices. Copy either folder **in full** to the appropriate location:

| Host | Personal skills | Project skills |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.agents/skills/` | `.agents/skills/` |

On Windows, `~` means your user profile. Restart the assistant session to ensure discovery. Locations follow the [Claude Code](https://code.claude.com/docs/en/skills) and [Codex](https://learn.chatgpt.com/docs/build-skills) documentation. Source skill folders do not contain binaries: build/install the CLI on a trusted PATH, or set `EMUDHRA_TRUST_AUDIT_BIN` to its absolute path before launching the assistant.

In Claude Code invoke `/endpoint-trust-audit` or `/project-trust-audit`; in Codex invoke `$endpoint-trust-audit` or `$project-trust-audit`. Ask “Audit this endpoint offline” or “Audit the current project without changes.”

Wrappers preserve arguments and exit codes:

```sh
sh /absolute/skill-dir/run.sh --format json          # endpoint skill
sh /absolute/skill-dir/run.sh /path/to/project --format json  # project skill
```

```powershell
& 'C:\absolute\endpoint-trust-audit\run.ps1' --format json
& 'C:\absolute\project-trust-audit\run.ps1' . --format json
```

They select the explicit binary path, a bundled binary, or a trusted PATH application. A missing binary produces installation guidance and exit 3; wrappers never download anything. Do not bypass organizational execution policy: invoke the trusted CLI directly if wrappers are restricted. Audit scope remains the user's project, not the skill directory.

## Output and interpretation

JSON includes `schema_version`, `tool_version`, `scope`, `verdict`, `action`, `exit_code`, `findings`, `data_sources`, `notes` and `errors`. Each finding includes evidence, confidence, remediation, sources and location references.

| Status | Meaning |
| --- | --- |
| `known_indicator` | Exact indicator or rule match; not proof of interception |
| `suspicious` | Heuristic requiring confirmation |
| `not_found` | Not found within completed checks |
| `unable_to_assess` | Incomplete evidence or unsupported/unavailable input; never a pass |

| Exit | Meaning |
| --- | --- |
| 0 | No action identified by completed checks; not a safety guarantee |
| 1 | Review required, including coverage gaps |
| 2 | Action required |
| 3 | Audit, input, integrity or output error |

`UNKNOWN` can coexist with action required. A stored key, blocklist entry or version string does not prove effective acceptance/rejection. The Rust CLI does not assert `EXPOSED` or `BLOCKED`. `INSECURE` means a recognized TLS-disabling setting was found; confirm actual use and report it first. Documentation matches are downgraded, and test fixtures still require human context.

Locations are opaque `file:<hash>` references, not filenames. Correlate a known project-relative path locally with `emudhra-trust-audit file-id path/to/file`. Raw source lines, personal paths, certificate subjects, proxy values and unrecognized version strings are withheld.

## Coverage, privacy and limitations

The scanner parses PEM/DER SPKIs and trusted entries in JKS/JCEKS (without decrypting private keys or verifying the keystore password digest). macOS keychain and Windows Root/CA/Disallowed enumeration require `--commands`; Windows update-policy parsing is also covered. Default macOS/Windows audits remain file-only.

Partial parsers cover npm, Yarn, pnpm, requirements, Poetry/uv/PDM/Cargo locks, Pipfile, Composer, Bundler, Hex, Go, `.nvmrc`, `.node-version`, `.go-version`, `.tool-versions` and simple mise pins. CI runtime pins and container refresh/digest patterns are inspected. Unsupported formats, malformed data, missing lockfiles, unknown branches and non-numeric/prerelease generic versions remain gaps. This is not a general CVE/SCA scanner or a package resolver.

Project reads are bounded to 20,000 directory entries and 1 MiB per file. Links/reparse points, special files, oversized files and invalid UTF-8 are excluded and reported. Build/dependency directories are skipped. `.ca-trust-audit-ignore` remains the exclusion filename; explicit exclusions are reported. Endpoint bundles and probe output are limited to 16 MiB; probes time out after 10 seconds.

System CA symlinks are followed intentionally. Use stable local snapshots: parent-directory replacement races are not fully isolated. Network mounts may cause OS traffic. Arbitrary external tools are not sandboxed. A container or WSL result applies only to that environment. Browser revocation, Windows CTL freshness, running-process caches, PKCS#12/PKCS#7 and effective validation across clients are not established. Python/certifi environments are not executed. Conventional certifi bundles and metadata under `VIRTUAL_ENV`/`CONDA_PREFIX` are read directly; inspect other environments through their lockfiles and explicit CA bundles.

**Sharing output with online Claude/Codex is separate from scanner networking.** For local-only handling, run the CLI and keep reports off external services. Opaque path hashes permit correlation and are not encryption. Do not have an assistant read raw files into chat to defeat redaction. Actual assistant discovery and real-device policies still require deployment-specific validation.

## Remediation and data

Update OS trust packages, browsers, runtimes and independent bundles through official channels. Restart processes; rebuild and redeploy virtual environments, CI/container images and applications. Never disable TLS verification or indiscriminately delete related roots. The audit never performs these changes. Scope credential rotation to evidence of actual connections, authentication and interception; neither blanket rotation nor blanket non-rotation follows from this scan.

Indicators and rules stay in `data/` with sources, dates and versions. SHA-256 normalizes CRLF/CR to LF; other byte changes are detected. These are consistency checks, not signatures. Embedded data is updated by reviewed commits and a new binary, never runtime fetches. Much of the fixed-version table is a 2026-10-21 [community-tracker](https://emudhra.we-have-a-problem.com/) snapshot; recheck vendor notices when maintaining it. See [AUDIT.md](AUDIT.md) for migration differences and remaining risks.

## Development, releases and license

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- data --verify
cargo run --locked --example maintenance -- skills
```

CI also runs cargo-deny for advisories, licenses and dependency sources. This adds no product runtime dependency. Release packaging includes the locked dependencies' license texts. The release workflow builds the five targets above, tests their binaries and generates archive `SHA256SUMS`; a `v*` tag publishes a Release, while manual runs only upload Actions artifacts. Do not create a release tag without explicit authorization.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [VALIDATION.md](VALIDATION.md) and [CHANGELOG.md](CHANGELOG.md). Licensed under **Apache-2.0**, with [LICENSE](LICENSE), [NOTICE](NOTICE) and packaged third-party notices. Synthetic certificate fixtures contain no private keys. No affiliation with eMudhra, Anthropic, OpenAI or GitHub is implied. The former Python package/module and Python-specific build/test/skill helpers have been removed; old validation remains in Git history.
