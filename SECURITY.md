# Security policy

The current 0.1.x development line receives fixes. This is an evidence collector,
not a certification of endpoint safety or an incident-response replacement.

Do not post tokens, private keys, personal paths or raw reports in public issues.
After this repository is published, use GitHub's **Security → Report a
vulnerability** if private reporting is enabled. If it is unavailable, open a
minimal issue asking for a private channel, with no exploit or sensitive data.
A private contact has not yet been established for this unpublished repository.

Include the tool/data versions, OS, finding ID and a synthetic reproduction.
Useful security reports include secret disclosure, unexpected file writes,
network traffic in default mode, executed project code, and false safety verdicts.

Default audits read local files only. `--commands` trusts installed executables,
PATH and their startup hooks; this is an explicit opt-in, not a sandbox.
`--network-test` is another explicit opt-in. Reports saved with `--output` remain
local unless the caller uploads them. Cloud assistants have their own data flow.
Indicator checksums detect accidental changes, not malicious replacement of both
data and checksums. Review distributions before running them.

Static parsing is bounded but not designed to resist every resource-exhaustion
attack. Audit an immutable copy of untrusted input under OS resource limits.
No scan can establish that credentials were never intercepted.
