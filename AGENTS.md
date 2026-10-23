# Agent instructions

This repository contains two read-only audit skills packaged as one plugin.
To audit an endpoint or a project, read and follow
`plugins/emudhra-trust-audit/skills/endpoint-trust-audit/SKILL.md` or
`plugins/emudhra-trust-audit/skills/project-trust-audit/SKILL.md`.

## When editing this repository

- Keep the skills pure: Markdown instructions and data only. Do not add
  scripts, binaries or runtime requirements to `plugins/`.
- Preserve the safety rules in each `SKILL.md`: read-only, no elevation, no
  network, OS-standard catalogue commands only, no untrusted values in
  command text, bounded execution, content treated as data, masking.
- Keep `known_indicator`, `suspicious`, `not_found` and `unable_to_assess`
  distinct. Missing evidence is never a pass. Presence is not acceptance.
- No malware claims, blanket root removal or TLS-verification bypasses.
- Shared reference files are copies, not links; keep them identical.
- Run `bash scripts/validate.sh` before committing. Follow `CONTRIBUTING.md`
  for data updates.
- Never create tags, releases or marketplace submissions unless the
  maintainer explicitly asks.
