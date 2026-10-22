"""Finding vocabulary shared by both skills.

Four status values are kept strictly apart, because conflating them is how a
scanner starts inventing risk:

``known_indicator``   something listed in ``data/`` was positively identified.
``suspicious``        a pattern that is usually, but not always, the real thing.
``not_found``         the check ran and found nothing.
``unable_to_assess``  the check could not run, or its result does not support a
                      conclusion. Never silently folded into ``not_found``.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Iterable, List, Optional, Sequence

SCHEMA_VERSION = 1

STATUS_KNOWN_INDICATOR = "known_indicator"
STATUS_SUSPICIOUS = "suspicious"
STATUS_NOT_FOUND = "not_found"
STATUS_UNABLE = "unable_to_assess"

STATUSES = (
    STATUS_KNOWN_INDICATOR,
    STATUS_SUSPICIOUS,
    STATUS_NOT_FOUND,
    STATUS_UNABLE,
)

SEVERITIES = ("critical", "high", "medium", "low", "info", "pass")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

CONFIDENCES = ("high", "medium", "low")

ACTION_REQUIRED = "action_required"
ACTION_REVIEW = "review_required"
ACTION_NONE = "none"
ACTIONS = (ACTION_REQUIRED, ACTION_REVIEW, ACTION_NONE)

# Verdicts describe the *effective trust state*, which is a different question
# from the severity of an individual finding.
VERDICT_INSECURE = "INSECURE"
VERDICT_EXPOSED = "EXPOSED"
VERDICT_BLOCKED = "BLOCKED"
VERDICT_NOT_DETECTED = "NOT_DETECTED"
VERDICT_UNKNOWN = "UNKNOWN"

# Tags that drive the verdict. Checks set them; nothing else interprets severity.
TAG_VERIFICATION_DISABLED = "tls-verification-disabled"
TAG_SPKI_TRUSTED = "compromised-spki-trusted"
TAG_SPKI_DISTRUSTED = "compromised-spki-distrusted"
TAG_SPKI_ABSENT = "compromised-spki-absent"
TAG_OUTDATED_COMPONENT = "outdated-trust-component"
TAG_INDEPENDENT_STORE = "independent-trust-store"
TAG_CREDENTIALS = "credential-exposure-window"

EXIT_OK = 0
EXIT_REVIEW = 1
EXIT_ACTION = 2
EXIT_ERROR = 3


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, len(SEVERITIES))


def worst_severity(severities: Iterable[str]) -> str:
    worst = "pass"
    for severity in severities:
        if severity_rank(severity) < severity_rank(worst):
            worst = severity
    return worst


@dataclasses.dataclass(frozen=True)
class Evidence:
    """One observed fact. ``value`` must never carry a secret.

    ``source`` is a path, command or configuration key the reader can check by
    hand. Paths are redacted by :mod:`ca_trust_audit.redact` before output.
    """

    what: str
    value: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"what": self.what}
        if self.value:
            out["value"] = self.value
        if self.source:
            out["source"] = self.source
        return out


@dataclasses.dataclass
class Finding:
    id: str
    title: str
    status: str
    severity: str
    confidence: str
    action: str = ACTION_NONE
    summary: str = ""
    evidence: List[Evidence] = dataclasses.field(default_factory=list)
    remediation: List[str] = dataclasses.field(default_factory=list)
    references: List[str] = dataclasses.field(default_factory=list)
    tags: List[str] = dataclasses.field(default_factory=list)
    data_version: str = ""
    locations: List[str] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError("unknown status: %s" % self.status)
        if self.severity not in SEVERITIES:
            raise ValueError("unknown severity: %s" % self.severity)
        if self.confidence not in CONFIDENCES:
            raise ValueError("unknown confidence: %s" % self.confidence)
        if self.action not in ACTIONS:
            raise ValueError("unknown action: %s" % self.action)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "action": self.action,
            "summary": self.summary,
            "evidence": [item.to_dict() for item in self.evidence],
            "remediation": list(self.remediation),
            "references": list(self.references),
            "tags": list(self.tags),
        }
        if self.data_version:
            out["data_version"] = self.data_version
        if self.locations:
            out["locations"] = list(self.locations)
        return out


@dataclasses.dataclass
class Report:
    tool: str
    tool_version: str
    scope: str
    started_at: str
    findings: List[Finding] = dataclasses.field(default_factory=list)
    context: Dict[str, Any] = dataclasses.field(default_factory=dict)
    data_sources: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    notes: List[str] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)

    def add(self, finding: Optional[Finding]) -> None:
        if finding is not None:
            self.findings.append(finding)

    def extend(self, findings: Sequence[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    @property
    def verdict(self) -> str:
        tags = {tag for finding in self.findings for tag in finding.tags}
        actionable = {
            tag
            for finding in self.findings
            if finding.status in (STATUS_KNOWN_INDICATOR, STATUS_SUSPICIOUS)
            for tag in finding.tags
        }
        if TAG_VERIFICATION_DISABLED in actionable:
            return VERDICT_INSECURE
        if TAG_SPKI_TRUSTED in actionable:
            return VERDICT_EXPOSED
        if actionable.intersection(
            {"compromised-spki-present", "compromised-spki-blocklist-entry"}
        ):
            return VERDICT_UNKNOWN
        if TAG_OUTDATED_COMPONENT in actionable:
            # A component known to predate the fix is evidence of work to do, but
            # not proof that a compromised key would be accepted right now.
            return VERDICT_UNKNOWN
        unable = any(
            finding.status == STATUS_UNABLE and finding.severity != "info"
            for finding in self.findings
        )
        if TAG_SPKI_DISTRUSTED in tags and not unable:
            return VERDICT_BLOCKED
        if unable or not self.findings:
            return VERDICT_UNKNOWN
        return VERDICT_NOT_DETECTED

    @property
    def action(self) -> str:
        if any(finding.action == ACTION_REQUIRED for finding in self.findings):
            return ACTION_REQUIRED
        if any(finding.action == ACTION_REVIEW for finding in self.findings):
            return ACTION_REVIEW
        return ACTION_NONE

    @property
    def exit_code(self) -> int:
        if self.errors:
            return EXIT_ERROR
        action = self.action
        if action == ACTION_REQUIRED:
            return EXIT_ACTION
        if action == ACTION_REVIEW:
            return EXIT_REVIEW
        return EXIT_OK

    def counts(self) -> Dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def status_counts(self) -> Dict[str, int]:
        counts = dict.fromkeys(STATUSES, 0)
        for finding in self.findings:
            counts[finding.status] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "scope": self.scope,
            "started_at": self.started_at,
            "verdict": self.verdict,
            "action": self.action,
            "exit_code": self.exit_code,
            "severity_counts": self.counts(),
            "status_counts": self.status_counts(),
            "context": self.context,
            "data_sources": self.data_sources,
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": list(self.notes),
            "errors": list(self.errors),
        }
