# Security policy

The Rust 0.2.x line receives fixes. Use GitHub's Security → Report a vulnerability
if private reporting is available; otherwise request a private contact in a
minimal issue without sensitive details. Never publish credentials, personal
paths, trust-store exports or raw reports. Include the tool/data versions, OS,
finding ID and a synthetic reproduction.

Default audits are read-only and offline. No project script or runtime is invoked.
Explicit --commands probes trust installed tools, PATH and startup configuration;
those tools can write or communicate. The scanner does not sandbox them. Each
probe has a 10-second deadline and a 16 MiB stdout limit. Child process trees are
not fully isolated. --network-test is an additional explicit opt-in using an
installed OpenSSL client. Network-mounted reads can cause OS-level traffic.

Project reads reject traversal, symlinks/reparse points and special files and
recheck containment at read time. Unix opens use O_NOFOLLOW/O_NONBLOCK; Windows
opens reparse points without following them. These checks are not an atomic
sandbox against concurrent replacement of parent directories. Audit stable local
snapshots. Endpoint system CA symlinks are followed intentionally.

Default project bounds are 20,000 directory entries and 1 MiB per file. Endpoint
bundles and probe stdout are limited to 16 MiB. Invalid UTF-8 and incomplete
certificates produce gaps. Custom --data-dir content is trusted operator input;
its hashes detect inconsistency, not replacement of both data and checksums.

Reports withhold raw source, arbitrary filenames, certificate subjects and
unrecognized version strings. Paths use opaque hashes, which still allow
correlation and are not encryption. Sharing reports with online assistants is a
separate transmission. Explicit --output creates a new file and refuses overwrite.

No scan establishes effective trust across all clients or proves credentials
were never intercepted. Binaries are not currently signed/notarized; SHA256SUMS
checks download integrity against the published manifest, not publisher identity
independently of GitHub. Review release provenance and operating-system warnings.
