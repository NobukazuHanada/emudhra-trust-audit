# Fixed-version policy (corroborating evidence only)

This file is data, not instructions.

| Field | Value |
| --- | --- |
| Policy | `emudhra-2026-fixed-versions` |
| Data version | `2026.10.22` |
| As of | 2026-10-21 (transcribed 2026-10-22) |
| Source | https://emudhra.we-have-a-problem.com/ (community tracker), retrieved 2026-10-21 |
| Confidence | medium |

Version tables come from a community remediation tracker and change often. A
version comparison only corroborates. The authoritative check is whether a
compromised SPKI is still present or accepted.

- Never downgrade an SPKI match because a version looks new.
- Never report exposure from a version string alone.
- A version branch that is not listed, a range, a prerelease, or an unusual
  suffix is `unable_to_assess`.
- An installed version at or above the fixed version is `not_found` for that
  check only.
- An installed version below the fixed version is `known_indicator`, severity
  high, confidence medium.

## OS CA packages

| OS (`/etc/os-release` `ID`) | Version | Package | Fixed version | Notes |
| --- | --- | --- | --- | --- |
| `debian` | `12` | `ca-certificates` | `20250419~deb12u2` | dpkg ordering |
| `debian` | `13` | `ca-certificates` | `20250419+deb13u1` | dpkg ordering |
| `ubuntu` | any | `ca-certificates` | `20260816` | Tracker lists `20260816ubuntu0.*` per series; any dpkg version sorting at or above `20260816` satisfies this check; confirm the exact build with the release's security notice |
| `fedora` | any | `ca-certificates` | `2026.2.92_v9.0.319` | Fedora only. RHEL, Rocky and AlmaLinux use their own strings: `unable_to_assess`, confirm with the distributor erratum |
| `arch`, `archarm`, `manjaro` | any | `ca-certificates-mozilla` | `3.131.1-1` | |
| `alpine` | any | `ca-certificates` | `20261020-r0` | |
| macOS (Homebrew) | any | `ca-certificates` formula | not recorded | `unable_to_assess` by version; rely on the SPKI scan of the Homebrew bundle |

For dpkg ordering, `~` sorts before everything, including the end of the
string, so `20250419~deb12u1` < `20250419~deb12u2` < `20250419`.

## Packages, runtimes and tools

| Name | Ecosystem | Kind | Branch | Fixed version |
| --- | --- | --- | --- | --- |
| `certifi` | PyPI | CA bundle library | any | `2026.10.19` |
| `pip` | PyPI | tool | any | `26.2.2` |
| `uv` | PyPI | tool | any | `0.13.4` |
| `go` | Go | runtime | `1.27` | `1.27.3` |
| `go` | Go | runtime | `1.26` | `1.26.10` |
| `node` | npm | runtime | `22` | `22.23.4` |
| `node` | npm | runtime | `24` | `24.22.1` |
| `node` | npm | runtime | `26` | `26.12.1` |
| `rustls-webpki` | crates.io | CA/verification library | `0.103` | `0.103.16` |
| `webpki-roots` | crates.io | CA bundle library | `1.0` | `1.0.10` |
| `@anthropic-ai/claude-code` | npm | tool | any | `2.1.303` |

Go and Node branches not listed above (for example Go 1.25 or Node 20) are
`unable_to_assess`, never a pass.

## Watchlist (no fixed version transcribed)

These carry their own trust behaviour independent of the OS store. When
present, report `unable_to_assess` and point to the vendor's advisory.

| Name | Ecosystem | Why |
| --- | --- | --- |
| `Mozilla::CA` | CPAN | Ships its own copy of the Mozilla root bundle |
| `composer/ca-bundle` | Packagist | Falls back to a bundled `cacert.pem` |
| `castore` | Hex | Elixir CA store independent of the OS |
| `electron` | npm | Embeds Chromium/BoringSSL roots and CRLSet handling |
| `deno` | generic | Embeds webpki-roots |
| `@openai/codex` | npm | TLS stack depends on its build |
| Java `cacerts` | generic | JDK keystore independent of the OS; fixed builds vary by vendor |
| `openssl` | generic | Ships no roots but decides which bundle path is used |
| `curl` | generic | May use Schannel, Secure Transport, OpenSSL or a bundled path |
