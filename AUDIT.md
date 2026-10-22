# Independent audit — 2026-10-22

The implementation handoff was read, then the source was independently reviewed
and exercised with new regression cases in a separate session. This is a local
review, not certification. No GitHub push, publication, remote configuration or
commit was performed. The repository arrived with its files untracked; that Git
state is preserved.

## Findings corrected

| Area | Observed problem | Correction |
| --- | --- | --- |
| Scan bypass | A JSON object could copy a dataset ID to bypass TLS-content checks | Only an entire object equal to a loaded dataset is excluded |
| Project boundaries | Readers trusted walk-time checks and accepted arbitrary relative paths | Reject absolute/traversal paths, recheck containment and every link component at read time; use O_NOFOLLOW where available |
| File safety | Ignore files and several endpoint bundle reads were unbounded; FIFOs could block | Bounded regular-file reader with fstat and O_NONBLOCK where available; bound ignore files; retain project 1 MiB ceiling |
| Coverage | Linked directories and unreadable directory certificates could be silently skipped | Report linked directories and incomplete/unparseable certificate sources |
| Windows | `--no-user-stores` did not prevent CurrentUser enumeration | Remove CurrentUser from the PowerShell probe and reject it from parsed results |
| Dependency/tool detection | `.nvmrc`, `.go-version`, `.tool-versions` produced generic ecosystem records that never reached policy comparison; mise syntax was not parsed | Map Node/Go ecosystems, normalize nodejs to node, parse simple mise `[tools]` strings |
| Input robustness | Valid JSON with wrong root/section types could crash lockfile processing | Validate JSON shapes and treat parser failure as incomplete coverage |
| False certainty | A manifest version starting with numbers could be treated as an exact pin despite range syntax | Require a complete numeric three-part exact version; otherwise preserve range uncertainty |
| Manifest coverage | Several inventoried manifests had no parser and no explicit coverage warning | Flag those manifests as unassessed |
| Secret output | CI version suffixes and raw CLI banners could carry arbitrary text into reports | Restrict CI versions to the existing safe representation and report extracted client versions only |
| False positive | `CURL_INSECURE=1` was asserted to disable standard curl verification | Remove the unsupported environment-variable assertion |
| Optional networking | Invalid ports/targets could be misinterpreted; IPv6 OpenSSL targets lacked brackets | Validate target syntax and port range before connection; bracket IPv6 |
| Documentation | Unconditional no-network language conflicted with opt-in probes; fixture attribution was implicit | Clarify CLI help, executable/mount/race limitations, quoted skill paths, and synthetic fixture licensing |

New regression cases are in `tests/test_independent_audit.py`; the Node name
expectation in the existing parser test was updated for policy normalization.

## Scope conclusions

- **macOS/Linux/Windows:** portable standard-library code; fixed argument vectors
  for platform probes; Windows store-scope regression added. Linux was executed.
  macOS and Windows behavior remains simulated by fixture tests.
- **Claude Code/Codex:** two independent folders with name/description frontmatter,
  quoted helper paths, shared scanner copied into each distribution, and no
  dependency on the other skill. Both frontmatters validate. Local installation
  paths agree with [Claude Code documentation](https://code.claude.com/docs/en/skills)
  and [Codex documentation](https://learn.chatgpt.com/docs/build-skills).
- **Read-only/offline:** default CLI paths do not execute external probes or
  initiate sockets; regression tests intercept those calls and compare repository
  contents. Report output and checksum regeneration remain explicit write modes.
  Network tests remain explicit, consent-gated skill actions. Public documentation
  retrieval and development dependency installation during this audit are separate
  from scanner execution.
- **Injection:** scanned project text is not executed. Subprocess calls use
  argument arrays and `shell=False`; PowerShell store scripts are fixed strings,
  never interpolated from repository content. The executable allowlist is not a
  sandbox and does not establish that PATH executables are trustworthy.
- **Secrets:** source matches and private-key bodies are not rendered; known
  environment secrets and home/user paths are scrubbed by CLI rendering. Tests
  cover source-line, dependency-URL and CI-version sentinels. Unknown secrets in
  arbitrary filenames, paths or trusted executable output cannot be universally
  recognized. Assistant service transmission is separate from scanner networking.
- **Detection:** SPKI presence is not promoted to effective acceptance or malware.
  Multiple dependency versions remain checked. Regex-based settings, comment/test
  fixtures, complex lock formats, and runtime selection require human review.
- **License/attribution:** Apache-2.0 LICENSE and NOTICE are present and bundled in
  wheel/skills. Tests use synthetic certificates and no private keys. Indicator
  facts cite sources; no third-party repair script is redistributed. This checks
  repository packaging and attribution, not the provenance of every historical
  contribution or a legal opinion.
- **CI:** workflow YAML parses; read-only GitHub permissions and the three-OS,
  Python 3.9/3.12/3.14 matrix are present. Actual GitHub runs were not triggered.

## Executed validation

| Check | Result |
| --- | --- |
| Full suite, Linux CPython 3.12.15 | **202 passed** |
| Full suite, Linux CPython 3.9.25 | **202 passed** |
| Ruff 0.17.1 lint | passed |
| Ruff format | passed (source and generated files present at check time) |
| Both skill-creator quick validations | passed |
| IOC schemas/checksums | verified |
| Production SPKIs against public impacted-intermediates JSON | 8/8 matched |
| sdist and wheel | built |
| Installed wheel outside checkout | data verification passed |
| Both standalone skill helpers outside checkout | data + audit JSON execution passed |
| Portable skills with unchanged-tree check | included in passing full suite |
| CI YAML | parsed |

The advisory comparison used the public
[impacted intermediate list](https://emudhra.we-have-a-problem.com/impacted-intermediates.json).
Version-policy data was inspected against the
[dated tracker](https://emudhra.we-have-a-problem.com/), but this audit did not
independently authenticate every vendor release or refresh the full policy table.
The standard curl environment-variable claim was checked against the
[curl manual](https://curl.se/docs/manpage.html).

An initial Python 3.9 verification command accidentally recreated the local dev
venv and interrupted concurrent checks. The 3.12 dev environment was restored,
a separate 3.9 environment was created, and all reported final checks were rerun
successfully. This affected development tools, not scanner runtime behavior.

Audited distributions are in `dist/audit/` (wheel, sdist, two skill ZIPs and
`skills/` folders). Older root `dist/` artifacts are pre-audit and must not be
published. Source remains the authority for future rebuilds.

## Remaining limitations

1. macOS/Windows real stores, permissions/localization, Python 3.14, GitHub CI,
   and actual assistant discovery/invocation still need execution on those hosts.
2. Cross-platform path checks are not an atomic sandbox against concurrently
   swapped parent directories. Use a stable local snapshot. Endpoint system CA
   symlinks are intentionally followed; network mounts can cause OS-level traffic.
3. `--commands` can trigger installed-tool hooks, writes, downloads or telemetry;
   trusted binaries and startup configuration are required. Capture is truncated
   after subprocess completion, so a hostile opt-in executable can consume memory.
4. Input bounds reduce resource risks but are not a full hostile-filesystem or
   hostile-regex sandbox. Custom indicator data is trusted operator input;
   checksums detect inconsistency, not malicious replacement of data and hashes.
5. Parsers are partial, not package resolvers. Simple mise pins are supported;
   advanced TOML and unparsed manifests produce coverage limitations. Version
   tables age, and native package-manager ordering is approximated in some cases.
6. Effective client chain validation, browser revocation freshness, Windows CTL
   freshness, Authenticode, Java PKCS#12 and already-running processes are not
   established by this offline scan. Optional TLS/chain probes use separate
   connections and cannot establish that the same chain was accepted.
