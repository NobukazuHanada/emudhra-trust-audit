# Validation

The Rust suite exercises observable audit and safety behavior using synthetic
certificates and temporary projects. It replaces the historical Python suite;
old test counts do not imply one-to-one test parity.

Required checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- data --verify
cargo run --locked --example maintenance -- skills
cargo run --locked --example maintenance -- licenses target/license-review
```

Use a new license output directory each time. The local toolchain is the pinned
stable Rust 1.99.1, also the declared MSRV. The Rust checks workflow runs the same
source on Linux, macOS and Windows, including both wrappers on Windows. Unix-only
filesystem tests are excluded on Windows; pure Windows record/policy tests run on
all hosts. CI also runs cargo-deny against the committed lockfile.

The Release artifacts workflow tests and builds macOS arm64/x86_64, Linux musl
x86_64/arm64 and Windows x86_64, runs each target executable, packages independent
skill folders and dependency licenses, and generates SHA256SUMS. A manual run
creates downloadable Actions artifacts but does not create a tag or Release.
See the Actions runs attached to a commit for final hosted results.

Tests do not establish universal real-store behavior, actual assistant discovery,
release signing/notarization, effective chain acceptance or absence of past
interception. See AUDIT.md and SECURITY.md for the remaining boundaries.

Local migration verification: Linux Rust 1.99.1 passes 46 behavioral tests,
formatting, warning-free Clippy, indicator verification, skill validation and
locked dependency license collection. A generated archive was extracted outside
the checkout: the executable verified its embedded data with an empty PATH, and
the bundled project wrapper returned the expected review result. No Python files
were present in the archive. Real hosted results are recorded in Actions.
