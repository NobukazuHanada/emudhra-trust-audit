# Agent instructions

This repository contains a Rust CLI and two read-only audit skills. Read the
matching `skills/endpoint-trust-audit/SKILL.md` or
`skills/project-trust-audit/SKILL.md` before auditing an endpoint or project.

## Safety invariants

- Audits never modify trust stores, dependencies, registry settings or input files.
- Default operation is file-only and offline. Executable probes require explicit
  `--commands`; `--no-commands` wins. Network probes additionally require explicit
  consent and `--network-test HOST`. Do not execute project scripts.
- `known_indicator`, `suspicious`, `not_found` and `unable_to_assess` are distinct.
  Missing evidence is never a pass. Presence is not effective trust acceptance.
- No malware claims, blanket root removal or TLS-verification bypasses.
- Never output raw source, secrets, command banners or personal filenames. File
  references are opaque hashes. Custom indicator data is trusted maintainer input.
- Keep indicators/rules in `data/`, with provenance and normalized checksums.
  Embedded data makes the release executable independent of external files.

## Development

Use the pinned stable Rust toolchain and committed Cargo.lock. Run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- data --verify
cargo run --locked --example maintenance -- skills
```

After a reviewed data change, generate checksums without overwriting the input:
`cargo run --locked -- data --checksums data > new-checksums.json`, inspect it,
then replace `data/checksums.json`, rebuild and verify. Do not redirect stdout
straight onto an input file. No Python is used for building, testing or running.

Release tags publish archives; manual workflow runs only build downloadable
Actions artifacts. Never create a tag unless the user explicitly requests it.
