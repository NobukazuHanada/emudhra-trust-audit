# Contributing

Use Rust 1.99.1 (stable, pinned in rust-toolchain.toml; also the declared MSRV).
Cargo.lock is committed for reproducible dependency selection. Newer toolchains
are not a substitute for validating the declared minimum. Keep changes narrowly
scoped and preserve the safety invariants in AGENTS.md.

Run `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked --all-targets`, `cargo run --locked -- data --verify`, and
`cargo run --locked --example maintenance -- skills` before submitting changes.
CI runs these on Linux, macOS and Windows. Unix-only FIFO/permission/link tests
are platform gated; Windows response parsing and scope logic run on every OS.

Add regression tests for observable behavior rather than source wording. Tests
must use synthetic certificates and secrets; do not upload real reports, trust
stores, credentials or personal paths. Fixtures are not to be installed as CAs.

Indicator updates need a source URL, retrieval/as-of date and dataset version.
Recheck vendor sources; the current version table is a dated community snapshot.
`cargo run --locked -- data --checksums data` prints a new checksum manifest to
stdout. Review and save it to data/checksums.json, then rebuild and verify.
LF, CRLF and CR are equivalent for these hashes; other byte changes are detected.
A checksum is not an authenticity signature. Runtime code never updates data.

Dependencies must have an acceptable license and a specific Cargo.lock entry.
CI uses cargo-deny for advisory, license and source checks without adding it to
product dependencies. `cargo run --locked --example maintenance -- licenses NEW_DIR`
checks declared license metadata and gathers third-party texts for packaging.
Run it after `cargo fetch --locked` so all resolved sources are available. Do not
commit generated license directories, build outputs or downloaded binaries.

`sh scripts/package.sh TARGET ABSOLUTE_BINARY NEW_OUTPUT_DIR` prepares an archive
with both READMEs, license notices, data and independently usable skill folders.
The Release artifacts workflow builds five targets and SHA256SUMS. Manual runs
upload Actions artifacts only. Pushing a v* tag publishes a GitHub Release; obtain
explicit release authorization before creating any tag. Keep translations aligned.
