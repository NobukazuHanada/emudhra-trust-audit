# Changelog

## 0.1.0 — Unreleased

- Continue the initial Raven-Code implementation with two independently
  distributable Claude Code/Codex skills and a shared Python scanner.
- Include dated eMudhra SPKI indicators, version policies, static TLS rules,
  schemas, checksums and synthetic certificate fixtures.
- Fix SARIF test setup to describe the TLS-verification finding it asserts.
- Withhold matched source lines and container values; redact reports and errors.
- Default to file-only endpoint checks; executable probes require `--commands`.
- Separate certificate presence from effective acceptance, keep independent
  runtime matches even when an OS blocklist contains the same key, and avoid
  attributing two separate network handshakes to one verified chain.
- Inspect every matching dependency version, disclose unsupported/skipped input,
  and restrict Fedora policy to Fedora.
- Add standalone skill builds, package data in wheels, 3-OS CI, documentation,
  security reporting guidance, Apache-2.0 license and non-affiliation notice.

### Independent audit corrections

- Recheck project containment, links and read limits; reject FIFO/device inputs.
- Require full indicator-data equality for self-scan exclusions.
- Compare Node/Go version files and simple mise tool pins against policy.
- Report unparsed manifests and unreadable certificate directory/override inputs.
- Handle malformed JSON lockfile shapes and preserve manifest range uncertainty.
- Honor Windows `--no-user-stores` before enumeration.
- Withhold arbitrary CI version suffixes and raw client banner output.
- Validate opt-in network targets and format IPv6 OpenSSL targets correctly.
- Remove the unsupported `CURL_INSECURE` environment-variable assertion.
- Add independent regression coverage and document isolation limitations.
