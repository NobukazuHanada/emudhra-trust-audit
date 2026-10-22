# Handoff validation — 2026-10-22

Repository: `ca-trust-audit` (local Git initialized on `main`; no commits,
remote, push or publication performed).

The existing scanner, data, fixtures and skills were retained and
completed. The original run had 156 passing tests and one failing SARIF test.
The SARIF fixture now includes the TLS-verification tag and expects INSECURE.
Behavioral fixes and 13 additional regression cases bring the total to 170.

## Executed locally

| Check | Result |
| --- | --- |
| Full pytest suite, Python 3.12.15 / Linux | 170 passed |
| Full pytest suite, Python 3.9.25 / Linux | 170 passed |
| Ruff check | passed |
| Ruff format --check | 50 files formatted |
| skill-creator quick_validate, both SKILL.md files | passed |
| Data schema and SHA-256 verification | passed |
| Eight production SPKIs compared to the public impacted-intermediates JSON | 8/8 matched |
| sdist and wheel build | passed |
| Installed wheel data verification outside checkout | passed |
| Standalone skills outside checkout, no bytecode writes | passed |
| Default endpoint JSON smoke test on Linux | exit 1, UNKNOWN (coverage gaps) |
| Project JSON smoke test on this scanner repository | exit 2, INSECURE (intentional insecure-code test fixtures) |

The self-scan result is expected: source fixtures deliberately contain unsafe TLS
settings. It is not an assertion that a running client is insecure. Confirm each
finding's location and status rather than suppressing tests globally.

## Artifacts

`dist/skills/endpoint-trust-audit/` and `dist/skills/project-trust-audit/` are
independently installable folders. Matching ZIPs, a wheel and an sdist are in
`dist/`. Generated artifacts are excluded from Git; regenerate from source for
publication. No third-party certificate, private key or repair script is bundled.

## Remaining validation and publication work

- Execute the configured macOS/Windows/Linux CI matrix after a separately
  authorized push. macOS/Windows commands currently have fixture-based coverage;
  real device/store permissions and vendor-specific behavior need validation.
- Python 3.14 is configured in CI but was not run locally.
- Verify actual assistant discovery and invocation in installed Claude Code and
  Codex sessions. Directory layout, frontmatter and standalone helper execution
  have been checked; interactive host integration has not been exercised here.
- Choose the GitHub owner/repository and enable private vulnerability reporting.
  There is no placeholder public repository URL or implied published release.
- Maintain dated IOC/version snapshots against primary vendor notices. The
  version table mostly retains the community tracker's 2026-10-21 snapshot.
- Effective per-client chain acceptance, browser policy, Authenticode and
  revocation freshness are not established by this static/file-only audit.
- See README for unsupported lockfile formats, scan bounds, privacy boundaries
  and opt-in executable/network probes. Exact key matches remain actionable
  without being mislabeled as proof of compromise or effective acceptance.

## Superseding independent audit

See [AUDIT.md](AUDIT.md) for the subsequent independent review, fixes and current
202-test results. The original 170-test handoff above is historical. Audited
artifacts are regenerated under `dist/audit/`; earlier `dist/` outputs predate
these fixes and must not be published.

## Final publication checks — 2026-10-22

The audited source was checked again before the initial public commit:
202 tests passed on Linux Python 3.12 and Python 3.9; Ruff lint and formatting,
both skill frontmatter validations, and IOC checksums passed. Public source
files were inspected for credentials, private keys, local account paths and
generated files. Matches were synthetic test values, not live credentials.
Virtual environments, caches, build outputs and all dist artifacts remain
excluded from Git. Apache-2.0 LICENSE and NOTICE are included.

The earlier handoff and audit Git-state descriptions above describe those
reviews, before publication. Platform and detection limitations in AUDIT.md
still apply; local tests do not establish successful hosted CI or real-device
validation on macOS and Windows.

## Rename and cross-platform correction — 2026-10-22

The project is now `emudhra-trust-audit`; earlier names and Git states in this
file are historical. The first published CI run exposed five failures on each
Windows Python version and an Ubuntu setup failure. Converting the incident
JSON from LF to CRLF reproduces the exact Windows digest mismatch
(`b15c2818bc01c563` versus `dafab7accb2fdc94`). The CLI correctly refused
unverified data with exit 3, which also caused the audit and portable-skill
failures. Data hashing now normalizes CRLF/CR to LF without ignoring other byte
changes. Git attributes also preserve LF in checkouts. Regression tests verify
all three newline forms, tamper detection, chunk boundaries, and standalone
skills with CRLF data.

Linux CI is pinned to Ubuntu 22.04: the original Ubuntu 26.04 runner could not
obtain Python 3.9. The matrix retains Python 3.9/3.12/3.14 on all three OSes.
Python 3.9 is a legacy compatibility target, not a promise of upstream security
support. See both READMEs for the support policy.

Local Python 3.9 and 3.12 each pass 207 tests. Ruff lint/format, both skill
validators and data verification pass. The renamed sdist and wheel build.
The English and Japanese READMEs have matching command examples and language
links. Hosted CI results are available in the repository's Actions tab; these
local results alone do not establish a hosted run's success.
