# Report template

Write the report in the user's language. Keep the section order. Replace the
angle-bracket placeholders. Omit no section; write "none" where empty.

## Classification

Every check produces exactly one status:

| Status | Meaning | Never means |
| --- | --- | --- |
| `known_indicator` | Exact match with an indicator or a recognised rule (SPKI hash, TLS-disabling setting, version below the fixed version) | Proof that a forged chain was accepted, malware, or interception |
| `suspicious` | Heuristic signal that needs human confirmation (name-only match, ambiguous setting) | A confirmed problem |
| `not_found` | The check ran completely and found nothing | Safety outside that check |
| `unable_to_assess` | The check could not run or could not finish, or OS-standard commands cannot answer it | A pass |

Confidence is `high`, `medium` or `low` and must say why when not `high`.

## Overall verdict

| Verdict | When |
| --- | --- |
| **ACTION REQUIRED** | Any `known_indicator` with severity critical or high |
| **REVIEW REQUIRED** | Otherwise, any `suspicious`, any medium `known_indicator`, or any in-scope `unable_to_assess` |
| **NO ACTION IDENTIFIED IN COMPLETED CHECKS** | Only `not_found` results and no in-scope gap |

Because effective trust is never fully assessable with OS-standard commands,
an endpoint audit is at least **REVIEW REQUIRED** in practice.

## Template

```text
# <Endpoint|Project> trust audit — eMudhra weak intermediate CA keys

Verdict: <ACTION REQUIRED | REVIEW REQUIRED | NO ACTION IDENTIFIED IN COMPLETED CHECKS>
Scope: <OS and version, or project root shown as "."; container/WSL note if any>
Indicator data: emudhra-weak-intermediates-2026 v2026.10.22 (facts as of 2026-10-21)
Version policy: emudhra-2026-fixed-versions v2026.10.22 (as of 2026-10-21, confidence medium)
Audit date: <YYYY-MM-DD>

Not detected does not mean safe. This audit reads local evidence only. It
cannot show that a forged certificate was never accepted or that no traffic
was intercepted. This incident is a CA key compromise, not malware.

## 1. TLS verification disabled
<Each critical TLS-disabling finding first, or "none found in completed checks">

## 2. Findings
| # | Status | Severity | Confidence | Check | Location (masked) | Evidence (masked) |
|---|--------|----------|------------|-------|-------------------|-------------------|
| 1 | known_indicator | high | high | <check id> | <label/path> | <hash, setting fragment, version> |

For each finding:
- Why it matters: <one or two sentences>
- What the user can do: <specific action for the user to take; the agent
  does not perform it>
- Source: <indicators.md / fixed-versions.md / tls-rules.md row and its URL>

## 3. Not checked or not assessable (unable_to_assess)
| Area | Reason | How the user could check it |
|------|--------|-----------------------------|

## 4. Credential guidance
<State from indicators.md: none / CREDENTIAL_REVIEW_REQUIRED /
CREDENTIAL_ACTION_REQUIRED / ESCALATE, and the evidence that supports it.
Never order blanket rotation and never say rotation is unnecessary.>

## 5. What was run
<List of catalogue block IDs that were run, with SUMMARY/END status. No
command output beyond the summary lines.>
```

## Masking rules for every report

- Replace the home directory with `~` and drop user names, host names and
  e-mail addresses from paths and output.
- Never print secret values: tokens, passwords, keys, `_authToken`, URLs with
  credentials, private keys, cookie values. Write `<redacted>`.
- Do not print certificate subjects other than the public indicator names from
  `indicators.md`.
- Quote at most the matched setting fragment, never whole lines or files.
- Project paths are shown relative to the project root.

## Remediation phrasing

Remediation is advice for the user. The agent does not run it during the
audit, does not edit files, and does not change trust settings. Typical
advice:

- Compromised SPKI in an OS bundle or store: apply the OS vendor's CA update
  through the normal update process, then re-run the audit.
- Compromised SPKI in an application or project bundle: update the package
  that ships the bundle (for example `certifi`) to at least the fixed version,
  or regenerate the bundle from an updated upstream source.
- TLS verification disabled: remove the setting; if a private or inspecting
  proxy CA is the reason, configure that CA explicitly instead.
- Never recommend disabling TLS verification, deleting roots wholesale, or
  running repair scripts from third-party sites.
