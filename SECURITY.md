# Security policy

## Supported versions

The latest commit on `main` (plugins 0.4.x, skills only) receives fixes. The
archived Rust CLI on `archive/rust-cli` is not maintained.

## Reporting a vulnerability

Use GitHub's **Security → Report a vulnerability** if private reporting is
available. Otherwise open a minimal issue asking for a private contact,
without details. Never publish credentials, personal paths, trust-store
exports or raw audit output. Include the plugin and data versions, OS, agent
(Claude Code or Codex) and a synthetic reproduction.

Relevant issues include: a catalogue command that can modify state, reach the
network, follow links unexpectedly or embed untrusted input in command text;
wording that lets repository content steer the agent; output that leaks
secrets or personal data; incorrect indicator data.

## Security model

- The skills are instructions and data. Enforcement is the agent's own
  permission system: review each command before approving it.
- Catalogue commands are constant text. File contents are passed on standard
  input; file names reach programs only through `find -exec`. `PATH` is fixed
  to OS directories on Linux and macOS.
- Each block runs once with a 120-second timeout and prints bounded summaries
  (capped line counts, truncated fragments).
- Repository content and command output are treated as untrusted data.
- On Windows, CA files named by environment variables are opened only on
  local drives; UNC and mapped network paths are refused, so no file-server
  connection (and no automatic Windows sign-in to it) is triggered.
- URL credentials are redacted before output, and `grep` skips FIFOs and
  devices.
- Project scans do not follow symbolic links or Windows reparse points.
  Endpoint scans read fixed system paths, which may themselves be links set up
  by the OS. Audit a stable local snapshot; concurrent changes are not
  isolated.
- A crafted file can contain a line beginning `FILE<TAB>` and so mislabel
  which file an SPKI match came from. The match itself cannot be forged by
  file content.
- The indicator data is a reviewed snapshot without signatures. Verify
  changes to `references/indicators.md` against the cited sources.

## Out of scope

No audit here proves that a forged certificate was never accepted or that no
credential was intercepted. The skills are not a malware scanner.
