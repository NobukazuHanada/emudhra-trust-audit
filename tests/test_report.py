from __future__ import annotations

import json

import pytest

from ca_trust_audit import report as report_module
from ca_trust_audit.model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    EXIT_ACTION,
    EXIT_ERROR,
    EXIT_OK,
    EXIT_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_SUSPICIOUS,
    STATUS_UNABLE,
    TAG_OUTDATED_COMPONENT,
    TAG_SPKI_ABSENT,
    TAG_SPKI_DISTRUSTED,
    TAG_SPKI_TRUSTED,
    TAG_VERIFICATION_DISABLED,
    VERDICT_BLOCKED,
    VERDICT_EXPOSED,
    VERDICT_INSECURE,
    VERDICT_NOT_DETECTED,
    VERDICT_UNKNOWN,
    Evidence,
    Finding,
    Report,
    worst_severity,
)


def make_report(*findings: Finding) -> Report:
    report = Report(
        tool="test", tool_version="0.0.0", scope="unit", started_at="2026-01-01T00:00:00Z"
    )
    report.extend(findings)
    return report


def finding(**kwargs) -> Finding:
    defaults = {
        "id": "X-1",
        "title": "title",
        "status": STATUS_NOT_FOUND,
        "severity": "info",
        "confidence": "high",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_finding_rejects_an_invalid_vocabulary() -> None:
    for bad in (
        {"status": "probably-bad"},
        {"severity": "apocalyptic"},
        {"confidence": "vibes"},
        {"action": "panic"},
    ):
        with pytest.raises(ValueError):
            finding(**bad)


def test_exit_codes_follow_the_strongest_action() -> None:
    assert make_report(finding()).exit_code == EXIT_OK
    assert make_report(finding(action=ACTION_REVIEW)).exit_code == EXIT_REVIEW
    assert (
        make_report(finding(action=ACTION_REVIEW), finding(action=ACTION_REQUIRED)).exit_code
        == EXIT_ACTION
    )
    broken = make_report(finding())
    broken.errors.append("data integrity failure")
    assert broken.exit_code == EXIT_ERROR


def test_verdict_precedence() -> None:
    disabled = finding(
        status=STATUS_KNOWN_INDICATOR, severity="critical", tags=[TAG_VERIFICATION_DISABLED]
    )
    trusted = finding(status=STATUS_KNOWN_INDICATOR, severity="critical", tags=[TAG_SPKI_TRUSTED])
    outdated = finding(
        status=STATUS_KNOWN_INDICATOR, severity="medium", tags=[TAG_OUTDATED_COMPONENT]
    )
    distrusted = finding(status=STATUS_KNOWN_INDICATOR, severity="info", tags=[TAG_SPKI_DISTRUSTED])
    absent = finding(status=STATUS_NOT_FOUND, severity="pass", tags=[TAG_SPKI_ABSENT])
    unable = finding(status=STATUS_UNABLE, severity="medium")

    assert make_report(disabled, trusted).verdict == VERDICT_INSECURE
    assert make_report(trusted, distrusted).verdict == VERDICT_EXPOSED
    assert make_report(outdated, absent).verdict == VERDICT_UNKNOWN
    assert make_report(distrusted, absent).verdict == VERDICT_BLOCKED
    assert make_report(absent).verdict == VERDICT_NOT_DETECTED
    assert make_report(absent, unable).verdict == VERDICT_UNKNOWN
    assert make_report().verdict == VERDICT_UNKNOWN


def test_a_tag_on_a_not_found_finding_does_not_raise_a_verdict() -> None:
    """Only a positive observation can make a verdict actionable."""
    not_found_but_tagged = finding(status=STATUS_NOT_FOUND, tags=[TAG_SPKI_TRUSTED])
    assert make_report(not_found_but_tagged).verdict != VERDICT_EXPOSED


def test_suspicious_counts_as_actionable_for_the_verdict() -> None:
    suspicious = finding(status=STATUS_SUSPICIOUS, severity="high", tags=[TAG_SPKI_TRUSTED])
    assert make_report(suspicious).verdict == VERDICT_EXPOSED


def test_informational_unable_findings_do_not_force_unknown() -> None:
    absent = finding(status=STATUS_NOT_FOUND, severity="pass", tags=[TAG_SPKI_ABSENT])
    context_only = finding(status=STATUS_UNABLE, severity="info")
    assert make_report(absent, context_only).verdict == VERDICT_NOT_DETECTED


def test_worst_severity() -> None:
    assert worst_severity(["info", "critical", "medium"]) == "critical"
    assert worst_severity([]) == "pass"


def test_json_output_is_machine_readable() -> None:
    report = make_report(
        finding(
            id="ENDPOINT-SPKI-TRUSTED",
            status=STATUS_KNOWN_INDICATOR,
            severity="critical",
            action=ACTION_REQUIRED,
            evidence=[Evidence(what="SPKI SHA-256", value="ab" * 32, source="/etc/ssl/certs")],
            remediation=["update the package"],
            tags=[TAG_SPKI_TRUSTED],
        )
    )
    payload = json.loads(report_module.render(report, "json"))
    assert payload["schema_version"] == 1
    assert payload["verdict"] == VERDICT_EXPOSED
    assert payload["action"] == ACTION_REQUIRED
    assert payload["exit_code"] == EXIT_ACTION
    assert payload["severity_counts"]["critical"] == 1
    assert payload["status_counts"][STATUS_KNOWN_INDICATOR] == 1
    entry = payload["findings"][0]
    assert entry["evidence"][0]["source"] == "/etc/ssl/certs"
    assert entry["remediation"] == ["update the package"]


def test_sarif_output_is_well_formed() -> None:
    report = make_report(
        finding(
            id="PROJECT-TLS-VERIFY-NPM-STRICT-SSL",
            status=STATUS_KNOWN_INDICATOR,
            severity="critical",
            action=ACTION_REQUIRED,
            locations=[".npmrc"],
            tags=[TAG_VERIFICATION_DISABLED],
        ),
        finding(id="PROJECT-INVENTORY", severity="info"),
    )
    document = json.loads(report_module.render(report, "sarif"))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "ca-trust-audit"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "PROJECT-TLS-VERIFY-NPM-STRICT-SSL",
        "PROJECT-INVENTORY",
    }
    assert run["results"][0]["level"] == "error"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".npmrc"
    )
    # A finding without a location must not carry an empty locations array.
    assert "locations" not in run["results"][1]
    assert run["invocations"][0]["exitCode"] == EXIT_ACTION
    assert run["properties"]["verdict"] == VERDICT_INSECURE


def test_text_output_explains_the_vocabulary() -> None:
    report = make_report(finding(status=STATUS_UNABLE, severity="medium", action=ACTION_REVIEW))
    report.notes.append("a note")
    text = report_module.render(report, "text")
    assert "VERDICT: UNKNOWN" in text
    assert "ACTION:  review required (exit code 1)" in text
    assert "unable to assess" in text
    assert "a note" in text
    assert "Nothing was modified, deleted or transmitted" in text


def test_text_output_lists_severities_or_none() -> None:
    assert "FINDINGS: none" in report_module.render(make_report(), "text")
    assert "FINDINGS: info=1" in report_module.render(make_report(finding()), "text")


def test_unknown_format_is_rejected() -> None:
    with pytest.raises(ValueError):
        report_module.render(make_report(), "yaml")


def test_findings_are_sorted_by_severity() -> None:
    report = make_report(
        finding(id="B", severity="info"),
        finding(id="A", severity="critical"),
        finding(id="C", severity="medium"),
    )
    assert [item.id for item in report_module.sort_findings(report.findings)] == ["A", "C", "B"]


def test_action_none_is_the_default() -> None:
    assert finding().action == ACTION_NONE
