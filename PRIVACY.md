# Privacy

Applies to the `endpoint-trust-audit` and `project-trust-audit` skills in this
repository. Last updated 2026-10-23.

## What the skills collect

Nothing is collected by the project. The skills contain no code that sends
data, no telemetry and no network calls. The maintainers receive nothing.

## What the agent reads locally

When you run an audit, your agent (Claude Code or Codex) runs read-only
commands on your computer. Depending on the skill they read:

- CA bundles, OS trust stores and keychains (certificates only), selected
  client configuration files, a fixed list of environment variable names,
  the OS CA package version, and two Windows registry values; or
- files in the repository you chose, with dependency and cache directories
  excluded.

## What leaves your computer

The command output and the report are part of your conversation with the
agent, so they are processed by the AI service you use (Anthropic for Claude
Code, OpenAI for Codex) under that service's terms and privacy policy. The
skills keep this small: commands print only labels, counts, SPKI hashes,
versions, matched setting fragments and, for lockfiles, the few truncated
lines that hold a version, never whole files. Credentials in URLs are
replaced with `<redacted>` before output. Reports mask home paths, user names, secret values and certificate
subjects. Masking is done by the agent following instructions, so review
output before sharing a report further.

## Your choices

You can decline any command when your agent asks for approval, and you can
uninstall the skills at any time (see the README).

## Contact

Questions: open an issue at
https://github.com/NobukazuHanada/emudhra-trust-audit/issues without
including personal data or raw audit output.
