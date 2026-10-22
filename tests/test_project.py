from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from ca_trust_audit import model, project
from ca_trust_audit.project.scan import ProjectContext
from conftest import read_fixture_cert, write


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def context(root: Path, fixture_data, **kwargs) -> ProjectContext:
    return ProjectContext(root=root, data=fixture_data, env={"HOME": str(root.parent)}, **kwargs)


def ids(report: model.Report) -> List[str]:
    return [finding.id for finding in report.findings]


def by_id(report: model.Report, finding_id: str) -> model.Finding:
    matches = [finding for finding in report.findings if finding.id == finding_id]
    assert matches, "%s not in %s" % (finding_id, ids(report))
    return matches[0]


def test_committed_bundle_with_compromised_key_is_critical(repo: Path, fixture_data) -> None:
    write(repo / "package.json", '{"name": "app"}')
    write(repo / "deploy/ca/cacert.pem", read_fixture_cert("weak-intermediate"))
    report = project.audit(context(repo, fixture_data))

    finding = by_id(report, "PROJECT-BUNDLE-COMPROMISED-SPKI")
    assert finding.severity == "critical"
    assert finding.status == model.STATUS_KNOWN_INDICATOR
    assert finding.locations == ["deploy/ca/cacert.pem"]
    assert report.verdict == model.VERDICT_UNKNOWN
    assert report.exit_code == model.EXIT_ACTION


def test_clean_bundle_is_a_pass_with_a_caveat(repo: Path, fixture_data) -> None:
    write(repo / "ca-bundle.pem", read_fixture_cert("unrelated"))
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-BUNDLE-CLEAN")
    assert finding.severity == "pass"
    assert "can still trust the root" in finding.summary


def test_related_root_in_a_bundle_is_informational(repo: Path, fixture_data) -> None:
    write(repo / "ca-bundle.pem", read_fixture_cert("related-root"))
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-BUNDLE-RELATED-ROOT")
    assert finding.severity == "info"
    assert finding.action == model.ACTION_NONE


def test_outdated_certifi_pin(repo: Path, fixture_data) -> None:
    write(repo / "requirements.txt", "certifi==2026.09.01\n")
    report = project.audit(context(repo, fixture_data))

    finding = by_id(report, "PROJECT-DEPENDENCY-OUTDATED")
    assert finding.action == model.ACTION_REQUIRED
    assert model.TAG_OUTDATED_COMPONENT in finding.tags
    assert model.TAG_INDEPENDENT_STORE in finding.tags
    assert "no operating system update will fix it" in finding.summary
    assert finding.locations == ["requirements.txt"]
    # Outdated is not the same as exposed.
    assert report.verdict == model.VERDICT_UNKNOWN


def test_current_certifi_pin_passes(repo: Path, fixture_data) -> None:
    write(repo / "requirements.txt", "certifi==2026.10.19\n")
    report = project.audit(context(repo, fixture_data))
    assert by_id(report, "PROJECT-DEPENDENCY-CURRENT").severity == "pass"


def test_range_dependency_is_undetermined_not_safe(repo: Path, fixture_data) -> None:
    write(repo / "requirements.txt", "certifi>=2026.01.01\n")
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-DEPENDENCY-RANGE")
    assert finding.status == model.STATUS_UNABLE
    assert finding.action == model.ACTION_REVIEW
    assert report.exit_code == model.EXIT_REVIEW


def test_watchlist_dependency_needs_a_human(repo: Path, fixture_data) -> None:
    write(
        repo / "composer.lock", '{"packages": [{"name": "composer/ca-bundle", "version": "1.5.0"}]}'
    )
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-WATCHLIST-DEPENDENCY")
    assert finding.status == model.STATUS_UNABLE
    assert finding.action == model.ACTION_REVIEW


def test_npmrc_strict_ssl_false_is_insecure(repo: Path, fixture_data) -> None:
    write(repo / ".npmrc", "strict-ssl=false\nregistry=https://registry.npmjs.org/\n")
    report = project.audit(context(repo, fixture_data))

    finding = by_id(report, "PROJECT-TLS-VERIFY-NPM-STRICT-SSL")
    assert finding.severity == "critical"
    assert model.TAG_VERIFICATION_DISABLED in finding.tags
    assert report.verdict == model.VERDICT_INSECURE
    assert finding.locations == [".npmrc"]


def test_go_insecure_skip_verify_in_source(repo: Path, fixture_data) -> None:
    write(repo / "main.go", "tls.Config{InsecureSkipVerify: true}\n")
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-TLS-VERIFY-GO-SKIP" in ids(report)


def test_suspicious_rule_is_not_reported_as_known(repo: Path, fixture_data) -> None:
    write(repo / "client.py", "requests.get(url, verify=False)\n")
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-TLS-VERIFY-PYTHON-REQUESTS")
    assert finding.status == model.STATUS_SUSPICIOUS
    assert finding.confidence == "medium"
    assert finding.action == model.ACTION_REVIEW


def test_documentation_mention_is_downgraded(repo: Path, fixture_data) -> None:
    write(
        repo / "docs/troubleshooting.md",
        "Never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production.\n",
    )
    report = project.audit(context(repo, fixture_data))

    finding = by_id(report, "PROJECT-TLS-VERIFY-NODE-ENV")
    assert finding.severity == "low"
    assert finding.status == model.STATUS_SUSPICIOUS
    assert finding.tags == []
    assert "documentation" in finding.title
    # Prose must not drive the verdict.
    assert report.verdict != model.VERDICT_INSECURE


def test_real_setting_and_documentation_are_separate_findings(repo: Path, fixture_data) -> None:
    write(repo / "docs/guide.md", "NODE_TLS_REJECT_UNAUTHORIZED=0 is dangerous\n")
    write(repo / "run.sh", "export NODE_TLS_REJECT_UNAUTHORIZED=0\n")
    report = project.audit(context(repo, fixture_data))
    matching = [f for f in report.findings if f.id == "PROJECT-TLS-VERIFY-NODE-ENV"]
    assert len(matching) == 2
    assert {f.severity for f in matching} == {"critical", "low"}


def test_ignore_file_excludes_and_says_so(repo: Path, fixture_data) -> None:
    write(repo / "package.json", '{"name": "app"}')
    write(repo / "tests/fixtures/bad.npmrc", "strict-ssl=false\n")
    write(repo / ".ca-trust-audit-ignore", "# intentional fixtures\ntests/fixtures/**\n")
    report = project.audit(context(repo, fixture_data))

    assert "PROJECT-TLS-VERIFY-NPM-STRICT-SSL" not in ids(report)
    inventory = by_id(report, "PROJECT-INVENTORY")
    assert any("excluded by .ca-trust-audit-ignore" in item.what for item in inventory.evidence)
    # The exclusion is also stated in the notes, so it can never pass unnoticed.
    assert any("excluded by .ca-trust-audit-ignore" in note for note in report.notes)
    assert any("tests/fixtures/bad.npmrc" in note for note in report.notes)


def test_exclusion_is_reported_even_without_an_inventory(repo: Path, fixture_data) -> None:
    write(repo / "tests/fixtures/bad.npmrc", "strict-ssl=false\n")
    write(repo / ".ca-trust-audit-ignore", "tests/fixtures/**\n")
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-INVENTORY" not in ids(report)
    assert any("excluded by .ca-trust-audit-ignore" in note for note in report.notes)


def test_excluded_directories_are_not_walked(repo: Path, fixture_data) -> None:
    write(repo / "package.json", '{"name": "app"}')
    write(repo / "node_modules/evil/cacert.pem", read_fixture_cert("weak-intermediate"))
    write(repo / ".venv/lib/certifi/cacert.pem", read_fixture_cert("weak-intermediate"))
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-BUNDLE-COMPROMISED-SPKI" not in ids(report)
    assert report.context["files_walked"] == 1


def test_container_without_ca_refresh(repo: Path, fixture_data) -> None:
    write(repo / "Dockerfile", "FROM debian:12\nRUN apt-get install -y curl\n")
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-CONTAINER-NO-CA-REFRESH")
    assert finding.status == model.STATUS_UNABLE
    assert finding.locations == ["Dockerfile"]


def test_container_with_ca_refresh_is_not_flagged(repo: Path, fixture_data) -> None:
    write(
        repo / "Dockerfile",
        "FROM debian:12\nRUN apt-get update && apt-get install -y ca-certificates\n",
    )
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-CONTAINER-NO-CA-REFRESH" not in ids(report)


def test_digest_pinned_base_image(repo: Path, fixture_data) -> None:
    write(
        repo / "Dockerfile",
        "FROM debian@sha256:0123456789abcdef\nRUN update-ca-certificates\n",
    )
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-CONTAINER-DIGEST-PINNED" in ids(report)


def test_containers_can_be_skipped(repo: Path, fixture_data) -> None:
    write(repo / "Dockerfile", "FROM debian:12\n")
    report = project.audit(context(repo, fixture_data, include_containers=False))
    assert "PROJECT-CONTAINER-NO-CA-REFRESH" not in ids(report)


def test_ci_pins_are_recorded(repo: Path, fixture_data) -> None:
    write(
        repo / ".github/workflows/ci.yml",
        "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: '20.11.0'\n",
    )
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-CI-PINNED-RUNTIME")
    assert any("node-version 20.11.0" in item.value for item in finding.evidence)


def test_empty_directory_reports_no_manifest(repo: Path, fixture_data) -> None:
    report = project.audit(context(repo, fixture_data))
    finding = by_id(report, "PROJECT-NO-MANIFEST")
    assert finding.status == model.STATUS_UNABLE
    assert report.exit_code == model.EXIT_REVIEW


def test_manifest_without_lockfile_only_when_dependencies_exist(repo: Path, fixture_data) -> None:
    write(repo / "package.json", json.dumps({"dependencies": {"left-pad": "^1.0.0"}}))
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-NO-LOCKFILE" in ids(report)

    write(repo / "package.json", json.dumps({"name": "app"}))
    report = project.audit(context(repo, fixture_data))
    assert "PROJECT-NO-LOCKFILE" not in ids(report)


def test_clean_project_is_not_detected(repo: Path, fixture_data) -> None:
    write(repo / "requirements.txt", "certifi==2026.10.19\n")
    write(repo / "src/app.py", "import requests\nrequests.get('https://example.org')\n")
    report = project.audit(context(repo, fixture_data))
    assert report.verdict == model.VERDICT_NOT_DETECTED
    assert report.exit_code == model.EXIT_OK
    assert "PROJECT-TLS-SETTINGS-CLEAN" in ids(report)


def test_scan_bundle_option(repo: Path, fixture_data) -> None:
    bundle = write(repo.parent / "external.pem", read_fixture_cert("weak-intermediate"))
    report = project.audit(context(repo, fixture_data), scan_bundle=str(bundle))
    finding = by_id(report, "PROJECT-SCAN-BUNDLE-COMPROMISED")
    assert finding.severity == "critical"

    report = project.audit(context(repo, fixture_data), scan_bundle=str(repo / "missing.pem"))
    assert by_id(report, "PROJECT-SCAN-BUNDLE-UNREADABLE").status == model.STATUS_UNABLE


def test_self_data_copy_is_not_scanned_against_itself(repo: Path, fixture_data) -> None:
    """A vendored copy of the ruleset lists the patterns; that is not a finding."""
    source = fixture_data.data_dir / "rules" / "insecure-tls.json"
    write(repo / "vendor/data/rules/insecure-tls.json", source.read_text(encoding="utf-8"))
    report = project.audit(context(repo, fixture_data))
    assert not [f for f in report.findings if f.id.startswith("PROJECT-TLS-VERIFY")]


def test_paths_are_repository_relative(repo: Path, fixture_data) -> None:
    write(repo / "deploy/ca/cacert.pem", read_fixture_cert("weak-intermediate"))
    report = project.audit(context(repo, fixture_data))
    serialized = json.dumps(report.to_dict())
    assert str(repo) not in serialized
    assert "deploy/ca/cacert.pem" in serialized
