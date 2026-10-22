# Agent instructions

This repository contains two read-only audit skills and the scanner they drive.
Codex reads this file. Claude Code users should use the matching skill;
the skill bodies are the detailed instructions.

## The two skills

| Skill | Question it answers | Instructions |
| --- | --- | --- |
| `endpoint-trust-audit` | Would a client on *this machine* accept a certificate signed with one of the compromised eMudhra intermediate CA keys? | [`skills/endpoint-trust-audit/SKILL.md`](skills/endpoint-trust-audit/SKILL.md) |
| `project-trust-audit` | Does *this repository* trust such a key, or switch certificate verification off? | [`skills/project-trust-audit/SKILL.md`](skills/project-trust-audit/SKILL.md) |

Read the matching SKILL.md before running anything, and follow its "Hard rules"
section.

## Commands

```bash
python3 bin/ca-trust-audit.py endpoint --format json     # this machine
python3 bin/ca-trust-audit.py project . --format json    # this repository
python3 bin/ca-trust-audit.py explain ENDPOINT-SPKI-TRUSTED
python3 bin/ca-trust-audit.py data                       # indicator provenance
```

On Windows use `py -3 bin\ca-trust-audit.py ...`.

Exit codes: `0` nothing to do, `1` review required, `2` action required, `3`
audit error. Treat a non-zero exit as information, not as a crash.

## Rules that apply to any agent working here

1. **Read-only by default.** Neither skill may change a trust store, install a
   package, edit a lock file or write a registry key. Remediation is printed for
   a human to run.
2. **File-only by default.** External executable probes require explicit `--commands`.
   **No network by default.** The endpoint skill connects only with an explicit
   `--network-test HOST`, after asking the user. Nothing is ever uploaded.
3. **No guessing.** Distinguish `known_indicator`, `suspicious`, `not_found` and
   `unable_to_assess`. `unable_to_assess` is not a pass.
4. **No malware claims.** This incident is a weak CA key, not an infection.
5. **No secrets in output.** Variable names and redacted paths only.
6. **Indicators are data.** Everything matched against lives in `data/` with its
   own sources, `as_of` date and `data_version`. Never hardcode an indicator in
   Python, and never fetch indicators at runtime.

## Working on the code

```bash
python3 -m pytest           # tests
python3 -m ruff check .     # lint
python3 bin/ca-trust-audit.py data --write-checksums   # after editing data/
```

New checks belong in `data/` when they are indicators or rules, and in
`src/ca_trust_audit/` when they are logic. Every new finding id needs an entry in
`src/ca_trust_audit/explanations.py`; a test enforces it.
