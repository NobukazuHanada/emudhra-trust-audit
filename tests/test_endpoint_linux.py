from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from ca_trust_audit import endpoint, model
from ca_trust_audit.endpoint.context import EndpointContext
from ca_trust_audit.endpoint.platforminfo import ca_package_findings, os_identifiers
from conftest import FakeRunner, ok, read_fixture_cert, write

UBUNTU_RELEASE = 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n'


def make_context(fs_root: Path, data, **kwargs) -> EndpointContext:
    runner = kwargs.pop("runner", FakeRunner())
    env: Dict[str, str] = kwargs.pop(
        "env", {"HOME": "/home/tester", "USER": "tester", "PATH": "/usr/bin"}
    )
    return EndpointContext(
        data=data, system="linux", env=env, runner=runner, fs_root=fs_root, **kwargs
    )


def ids(findings: List[model.Finding]) -> List[str]:
    return [finding.id for finding in findings]


def by_id(report: model.Report, finding_id: str) -> model.Finding:
    matches = [finding for finding in report.findings if finding.id == finding_id]
    assert matches, "%s not in %s" % (finding_id, ids(report.findings))
    return matches[0]


def test_compromised_key_presence_does_not_prove_acceptance(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(
        fs_root / "etc/ssl/certs/ca-certificates.crt",
        read_fixture_cert("unrelated") + read_fixture_cert("weak-intermediate"),
    )
    report = endpoint.audit(make_context(fs_root, fixture_data))

    finding = by_id(report, "ENDPOINT-SPKI-TRUSTED")
    assert finding.status == model.STATUS_KNOWN_INDICATOR
    assert finding.severity == "critical"
    assert finding.action == model.ACTION_REQUIRED
    assert "compromised-spki-present" in finding.tags
    assert report.verdict == model.VERDICT_UNKNOWN
    assert report.exit_code == model.EXIT_ACTION
    # An exposure window must trigger the conditional credential guidance.
    credential = by_id(report, "ENDPOINT-CREDENTIAL-REVIEW")
    assert credential.status == model.STATUS_UNABLE
    assert credential.action == model.ACTION_REVIEW


def test_clean_bundle_is_not_detected_not_safe(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    report = endpoint.audit(make_context(fs_root, fixture_data))

    finding = by_id(report, "ENDPOINT-SPKI-ABSENT")
    assert finding.status == model.STATUS_NOT_FOUND
    assert finding.severity == "pass"
    assert "does not prove" in finding.summary
    assert "ENDPOINT-SPKI-TRUSTED" not in ids(report.findings)
    assert "ENDPOINT-CREDENTIAL-REVIEW" not in ids(report.findings)


def test_blocklisted_key_is_reported_as_the_desired_state(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    write(
        fs_root / "etc/pki/ca-trust/source/blocklist/weak.pem",
        read_fixture_cert("weak-intermediate"),
    )
    report = endpoint.audit(make_context(fs_root, fixture_data))

    finding = by_id(report, "ENDPOINT-SPKI-DISTRUSTED")
    assert finding.severity == "info"
    assert finding.action == model.ACTION_NONE
    assert "compromised-spki-blocklist-entry" in finding.tags
    assert "ENDPOINT-SPKI-TRUSTED" not in ids(report.findings)


def test_related_root_presence_is_informational_only(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("related-root"))
    report = endpoint.audit(make_context(fs_root, fixture_data))

    finding = by_id(report, "ENDPOINT-RELATED-ROOT-PRESENT")
    assert finding.severity == "info"
    assert finding.action == model.ACTION_NONE
    assert finding.tags == []
    assert report.verdict != model.VERDICT_EXPOSED


def test_unreadable_store_is_unable_to_assess_not_a_pass(fs_root: Path, fixture_data) -> None:
    path = write(fs_root / "etc/ssl/certs/ca-certificates.crt", "not a certificate at all")
    assert path.exists()
    report = endpoint.audit(make_context(fs_root, fixture_data))

    finding = by_id(report, "ENDPOINT-STORE-UNREADABLE")
    assert finding.status == model.STATUS_UNABLE
    assert finding.action == model.ACTION_REVIEW
    assert report.verdict == model.VERDICT_UNKNOWN


def test_no_store_at_all_is_unable_to_assess(fs_root: Path, fixture_data) -> None:
    report = endpoint.audit(make_context(fs_root, fixture_data))
    finding = by_id(report, "ENDPOINT-NO-STORE-FOUND")
    assert finding.status == model.STATUS_UNABLE
    assert report.verdict == model.VERDICT_UNKNOWN
    assert report.exit_code == model.EXIT_REVIEW


def test_outdated_ca_package_is_action_required_but_not_exposed(
    fs_root: Path, fixture_data
) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    runner = FakeRunner(
        {("dpkg-query", "-W", "-f=${Version}", "ca-certificates"): ok("20240203\n")},
        available=["dpkg-query"],
    )
    report = endpoint.audit(make_context(fs_root, fixture_data, runner=runner))

    finding = by_id(report, "ENDPOINT-CA-PACKAGE-OUTDATED")
    assert finding.status == model.STATUS_KNOWN_INDICATOR
    assert finding.action == model.ACTION_REQUIRED
    assert model.TAG_OUTDATED_COMPONENT in finding.tags
    # Known-outdated is not proof of effective trust.
    assert report.verdict == model.VERDICT_UNKNOWN
    assert report.exit_code == model.EXIT_ACTION


def test_current_ca_package_passes(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    runner = FakeRunner(
        {("dpkg-query", "-W", "-f=${Version}", "ca-certificates"): ok("20260816ubuntu0.22.04.1\n")},
        available=["dpkg-query"],
    )
    report = endpoint.audit(make_context(fs_root, fixture_data, runner=runner))

    finding = by_id(report, "ENDPOINT-CA-PACKAGE-CURRENT")
    assert finding.severity == "pass"
    assert "does not prove" in finding.summary
    assert report.exit_code == model.EXIT_OK


def test_unknown_distribution_has_no_policy_row(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", 'ID=gentoo\nVERSION_ID="2.14"\n')
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    ctx = make_context(fs_root, fixture_data)
    findings = ca_package_findings(ctx)
    assert ids(findings) == ["ENDPOINT-CA-PACKAGE-NO-POLICY"]
    assert findings[0].status == model.STATUS_UNABLE
    assert os_identifiers(ctx) == ["gentoo"]


def test_verification_disabled_env_outranks_everything(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(
        fs_root / "etc/ssl/certs/ca-certificates.crt",
        read_fixture_cert("weak-intermediate"),
    )
    env = {"HOME": "/home/tester", "PATH": "/usr/bin", "GIT_SSL_NO_VERIFY": "1"}
    report = endpoint.audit(make_context(fs_root, fixture_data, env=env))

    finding = by_id(report, "ENDPOINT-VERIFICATION-DISABLED-ENV")
    assert finding.severity == "critical"
    assert model.TAG_VERIFICATION_DISABLED in finding.tags
    assert report.verdict == model.VERDICT_INSECURE


def test_custom_ca_bundle_from_env_is_scanned(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    write(fs_root / "opt/corp/ca.pem", read_fixture_cert("weak-intermediate"))
    env = {"HOME": "/home/tester", "PATH": "/usr/bin", "REQUESTS_CA_BUNDLE": "/opt/corp/ca.pem"}
    report = endpoint.audit(make_context(fs_root, fixture_data, env=env))

    override = by_id(report, "ENDPOINT-CA-OVERRIDE-ENV")
    assert override.action == model.ACTION_REVIEW
    assert any("REQUESTS_CA_BUNDLE" in item.what for item in override.evidence)
    # The bundle the variable points at is matched like any other trust source.
    assert "ENDPOINT-SPKI-TRUSTED" in ids(report.findings)
    assert report.verdict == model.VERDICT_UNKNOWN


def test_proxy_values_are_never_echoed(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    secret = "http://user:hunter2@proxy.internal:8080"
    env = {"HOME": "/home/tester", "PATH": "/usr/bin", "HTTPS_PROXY": secret}
    report = endpoint.audit(make_context(fs_root, fixture_data, env=env))

    finding = by_id(report, "ENDPOINT-PROXY-CONFIGURED")
    assert finding.severity == "info"
    import json as _json

    assert "hunter2" not in _json.dumps(report.to_dict())
    assert any(item.value == "HTTPS_PROXY" for item in finding.evidence)


def test_container_and_wsl_context_are_reported(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    (fs_root / ".dockerenv").write_text("", encoding="utf-8")
    write(fs_root / "proc/version", "Linux version 5.15.0-microsoft-standard-WSL2")
    report = endpoint.audit(make_context(fs_root, fixture_data))

    assert "ENDPOINT-CONTAINER-CONTEXT" in ids(report.findings)
    assert "ENDPOINT-WSL-CONTEXT" in ids(report.findings)
    # Context findings are informational and must not force a verdict on their own.
    assert by_id(report, "ENDPOINT-CONTAINER-CONTEXT").severity == "info"


def test_home_directory_is_redacted(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    env = {
        "HOME": "/home/tester",
        "USER": "tester",
        "PATH": "/usr/bin",
        "SSL_CERT_FILE": "/home/tester/ca.pem",
    }
    report = endpoint.audit(make_context(fs_root, fixture_data, env=env))

    import json as _json

    serialized = _json.dumps(report.to_dict())
    assert "/home/tester" not in serialized
    assert "~/ca.pem" in serialized


def test_ca_conf_disabled_entries_are_reported(fs_root: Path, fixture_data) -> None:
    write(fs_root / "etc/os-release", UBUNTU_RELEASE)
    write(fs_root / "etc/ssl/certs/ca-certificates.crt", read_fixture_cert("unrelated"))
    write(
        fs_root / "etc/ca-certificates.conf",
        "# comment\nmozilla/Some_Other_CA.crt\n!mozilla/Fixture_Related_Root_CA_-_T0.crt\n",
    )
    report = endpoint.audit(make_context(fs_root, fixture_data))
    finding = by_id(report, "ENDPOINT-LINUX-CA-CONF")
    assert finding.evidence[0].what == "disabled"
