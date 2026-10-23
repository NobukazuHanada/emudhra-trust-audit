# Contributing

The product is two plugins with one skill each:
`plugins/endpoint-trust-audit/skills/endpoint-trust-audit/` and
`plugins/project-trust-audit/skills/project-trust-audit/`. They must stay
pure: Markdown instructions and data only, no scripts, binaries or
runtime requirements for users. Keep changes narrow and preserve the safety
rules in each `SKILL.md`.

## Rules for skill changes

- New commands go into a catalogue (`references/commands-*.md`) as constant
  blocks: read-only, OS-standard tools only, fixed `PATH` on POSIX, no
  untrusted value in command text, bounded output, and a clear way to tell
  complete from incomplete results.
- Anything not checkable with OS-standard commands is documented as
  `unable_to_assess`, never approximated.
- Keep `SKILL.md` under 500 lines and its `description` under 1,024
  characters; `name` must equal the folder name.
- Keep both plugins at the same `version` in all four manifests, and list
  them in the same order in both marketplace files.
- Never use symbolic links. Shared files are copied: `indicators.md`,
  `fixed-versions.md` and `report-template.md` must be byte-identical in both
  skills, and CI checks this.

## Indicator and policy updates

Every change needs a source URL, retrieval date, "as of" date and a new data
version in the file header. Update both skill copies, every embedded hash
list (the POSIX SPKI filters and the Windows blocks), and the version line in
`report-template.md`. All indicators are currently ECDSA P-384; the Windows
blocks hash only P-384 keys, so a different key type requires changing those
blocks. Do not add certificate bodies whose redistribution terms are unknown.

## Local checks

CI runs `scripts/validate.sh`, which needs `bash`, `jq`, `awk`, `grep` and
`openssl` (maintainer tools only; users need none of them):

```sh
bash scripts/validate.sh
```

It checks manifests, skill frontmatter and headings, links, shared-file
copies, indicator consistency, forbidden commands in catalogue blocks, file
types and sizes, README parity, and runs the POSIX catalogue blocks against
synthetic fixtures. On Windows, CI also runs the PowerShell blocks.

If you have Claude Code, `claude plugin validate --strict .`,
`claude plugin validate --strict ./plugins/endpoint-trust-audit` and
`claude plugin validate --strict ./plugins/project-trust-audit` validate the
manifests.

## Documentation

`README.md` (English) and `README.ja.md` (Japanese) must keep the same
sections and facts. Update `CHANGELOG.md` and bump the `version` in all four
plugin manifests for user-visible changes.
