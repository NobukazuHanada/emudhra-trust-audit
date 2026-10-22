"""Rendering: human-readable text, machine-readable JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from . import __version__
from .model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    SEVERITIES,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_SUSPICIOUS,
    STATUS_UNABLE,
    Finding,
    Report,
    severity_rank,
)

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "pass": "none",
}

STATUS_LABEL = {
    STATUS_KNOWN_INDICATOR: "known indicator",
    STATUS_SUSPICIOUS: "suspicious",
    STATUS_NOT_FOUND: "not found",
    STATUS_UNABLE: "unable to assess",
}

ACTION_LABEL = {
    ACTION_REQUIRED: "action required",
    ACTION_REVIEW: "review required",
    ACTION_NONE: "no action from this check",
}

VERDICT_EXPLANATION = {
    "EXPOSED": "a client on this scope would still accept a chain through a compromised key",
    "BLOCKED": "the compromised keys were positively found to be rejected",
    "INSECURE": "certificate verification is switched off somewhere; fix that first",
    "NOT_DETECTED": "no compromised key was found, and no effective-trust test proved rejection",
    "UNKNOWN": "the evidence does not support any verdict",
}

LEGEND = (
    "status: known indicator = matched data/ exactly | suspicious = pattern match, confirm by hand | "
    "not found = checked, nothing found | unable to assess = the check could not reach a conclusion"
)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (severity_rank(f.severity), f.id))


def render_json(report: Report, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False) + "\n"


def render_text(report: Report, *, color: bool = False) -> str:
    lines: List[str] = []
    lines.append("emudhra-trust-audit %s - %s" % (report.tool_version, report.tool))
    lines.append("scope:   %s" % report.scope)
    lines.append("started: %s" % report.started_at)
    for key, value in sorted(report.context.items()):
        if isinstance(value, (str, int, float, bool)) and value != "":
            lines.append("%-8s %s" % (key + ":", value))
    lines.append("")
    verdict = report.verdict
    lines.append("VERDICT: %s - %s" % (verdict, VERDICT_EXPLANATION.get(verdict, "")))
    lines.append("ACTION:  %s (exit code %d)" % (ACTION_LABEL[report.action], report.exit_code))
    counts = report.counts()
    summary = ", ".join("%s=%d" % (name, counts[name]) for name in SEVERITIES if counts[name])
    lines.append("FINDINGS: %s" % (summary or "none"))
    lines.append("")

    for dataset in report.data_sources:
        lines.append(
            "data: %-18s version %s (as of %s)"
            % (
                dataset.get("id") or dataset.get("dataset"),
                dataset.get("data_version"),
                dataset.get("as_of"),
            )
        )
    lines.append("")

    if report.errors:
        lines.append("ERRORS")
        for error in report.errors:
            lines.append("  ! %s" % error)
        lines.append("")

    for finding in sort_findings(report.findings):
        lines.append(
            "[%s] %s  (%s, confidence %s)"
            % (
                finding.severity.upper(),
                finding.id,
                STATUS_LABEL[finding.status],
                finding.confidence,
            )
        )
        lines.append("  %s" % finding.title)
        if finding.summary:
            lines.append("  %s" % finding.summary)
        if finding.evidence:
            lines.append("  evidence:")
            for item in finding.evidence:
                text = "    - %s" % item.what
                if item.value:
                    text += ": %s" % item.value
                if item.source:
                    text += "  [%s]" % item.source
                lines.append(text)
        if finding.remediation:
            lines.append("  what to do:")
            for step in finding.remediation:
                lines.append("    * %s" % step)
        if finding.references:
            lines.append("  sources:")
            for reference in finding.references:
                lines.append("    - %s" % reference)
        lines.append("")

    if report.notes:
        lines.append("NOTES")
        for note in report.notes:
            lines.append("  - %s" % note)
        lines.append("")

    lines.append(LEGEND)
    lines.append(
        "Nothing was modified, deleted or transmitted by this run. "
        "Remediation commands are printed for a human to run, never executed."
    )
    return "\n".join(lines) + "\n"


def render_sarif(report: Report) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for finding in sort_findings(report.findings):
        rules.setdefault(
            finding.id,
            {
                "id": finding.id,
                "name": finding.id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.summary or finding.title},
                "help": {
                    "text": "\n".join(finding.remediation) or "No remediation step recorded.",
                },
                "properties": {
                    "tags": list(finding.tags),
                    "security-severity": _security_severity(finding.severity),
                    "status": finding.status,
                    "confidence": finding.confidence,
                },
            },
        )
        result: Dict[str, Any] = {
            "ruleId": finding.id,
            "level": SARIF_LEVEL.get(finding.severity, "note"),
            "message": {
                "text": "%s [%s, confidence %s] %s"
                % (finding.title, STATUS_LABEL[finding.status], finding.confidence, finding.summary)
            },
            "properties": {
                "status": finding.status,
                "confidence": finding.confidence,
                "action": finding.action,
                "evidence": [item.to_dict() for item in finding.evidence],
            },
        }
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location, "uriBaseId": "%SRCROOT%"},
                }
            }
            for location in finding.locations
        ]
        if locations:
            result["locations"] = locations
        results.append(result)

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "emudhra-trust-audit",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not report.errors,
                        "exitCode": report.exit_code,
                        "commandLine": report.scope,
                    }
                ],
                "properties": {
                    "verdict": report.verdict,
                    "action": report.action,
                    "dataSources": report.data_sources,
                    "notes": report.notes,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _security_severity(severity: str) -> str:
    return {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "3.0",
        "info": "0.0",
        "pass": "0.0",
    }.get(severity, "0.0")


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "text":
        return render_text(report)
    raise ValueError("unknown output format: %s" % fmt)
