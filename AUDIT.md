# Rust migration review

This is a maintainer review, not independent certification. The earlier review
applied to the implementation at commit 418eef09e8b67f626c8dba67464d9b1005998087;
its conclusions are not automatically carried over to the Rust replacement.

## Preserved evidence and boundaries

| Area | Rust behavior and regression coverage |
| --- | --- |
| Trust evidence | Synthetic PEM/DER SPKI matching; JKS trusted entries; blocklist presence never suppresses independent-store matches |
| Data integrity | Embedded/offline data, provenance, schema subset validation; LF/CRLF/CR normalization and tamper rejection |
| Project scope | Traversal, absolute paths, symlinks/reparse points, FIFO, file limits, invalid UTF-8 and unavailable files produce errors/gaps |
| Dependency coverage | npm/Yarn/pnpm, requirements, TOML locks, Pipfile, Composer, Gemfile, Hex, Go and tool pins; malformed/unsupported input is disclosed |
| Versions | Every matching version remains checked; unknown branches/ranges are not passes; Debian ordering is retained |
| TLS settings | 19 data-driven rules; documentation is downgraded; dataset-ID spoofing cannot suppress inspection |
| Windows | Static read-only store script, actual CurrentUser exclusion, pure record/policy parsers tested with LF/CRLF and invalid output |
| Privacy | Source lines, subjects, arbitrary path names, raw banners and unresolved versions withheld; stable opaque file references |
| Execution | No shell interpolation; default scans invoke no tools; opt-in probes use bounded capture and timeout |
| Distribution | No runtime interpreter; compiled data; standalone binary test outside checkout with empty PATH |

## Explicit migration differences

Python/certifi interpreters are not executed. Inspect each environment's dependency
lockfiles and supply its CA bundle explicitly. No backend is silently described as
fully covered. Generic versions with prerelease or unusual suffixes produce a gap
rather than an optimistic comparison. The old Python module/environment API is
removed. `--data-dir` is the explicit reviewed-data override. Project exclusions
retain `.ca-trust-audit-ignore`. Human-readable file paths are replaced by opaque
references; `file-id RELATIVE_PATH` computes the same reference locally.

The optional network probe invokes installed OpenSSL with verification enabled.
It does not equate failure with CA rejection or extrapolate one connection to
other clients. PKCS#12/PKCS#7, browser policies, effective chain validation,
revocation/CTL freshness and running-process state are not established.

## Remaining risks

- Stable snapshots are required. Parent-directory replacement races are not
  atomically excluded on every OS; endpoint system symlinks are followed.
- Installed probes, PATH and startup hooks are trusted opt-ins, not a sandbox.
  Descendant processes and network mounts are outside complete isolation.
- Parsing is bounded and partial, not a resolver or general vulnerability scanner.
  Checksums are not authenticity signatures; custom data is trusted input.
- Vendor policy snapshots age. A key match is not proof of acceptance, malware or
  credential interception. Review rotations according to actual evidence.
- Hosted OS tests do not cover every real store, enterprise policy or assistant
  discovery/invocation. Downloaded macOS/Windows binaries are unsigned.
