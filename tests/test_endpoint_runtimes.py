"""Runtimes with their own trust store, and the clients that read it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ca_trust_audit import model
from ca_trust_audit.endpoint import runtimes
from ca_trust_audit.endpoint.context import EndpointContext
from conftest import FakeRunner, fail, ok, read_fixture_cert, write
from test_jks import build_jks, der_of

ENV = {"HOME": "/home/tester", "USER": "tester", "PATH": "/usr/bin"}


def context(fixture_data, runner: FakeRunner, fs_root: Path) -> EndpointContext:
    return EndpointContext(
        data=fixture_data, system="linux", env=ENV, runner=runner, fs_root=fs_root
    )


def ids(findings: List[model.Finding]) -> List[str]:
    return [finding.id for finding in findings]


def test_node_version_and_builtin_roots(tmp_path: Path, fixture_data) -> None:
    runner = FakeRunner(
        {
            ("node", "--version"): ok("v24.21.0\n"),
            ("node", "-p"): ok(read_fixture_cert("weak-intermediate")),
        },
        available=["node"],
    )
    findings, sources = runtimes.check_node(context(fixture_data, runner, tmp_path))
    assert ids(findings) == ["ENDPOINT-COMPONENT-OUTDATED"]
    assert "24.22.1" in findings[0].summary
    assert model.TAG_OUTDATED_COMPONENT in findings[0].tags
    assert sources[0].role == "independent"
    assert sources[0].count == 1


def test_node_on_an_uncovered_branch_is_unable_to_assess(tmp_path: Path, fixture_data) -> None:
    runner = FakeRunner({("node", "--version"): ok("v20.11.0\n")}, available=["node"])
    findings, _sources = runtimes.check_node(context(fixture_data, runner, tmp_path))
    assert ids(findings) == ["ENDPOINT-COMPONENT-BRANCH-UNKNOWN"]
    assert findings[0].status == model.STATUS_UNABLE
    assert findings[0].action == model.ACTION_REVIEW


def test_node_root_dump_failure_is_recorded_as_unreadable(tmp_path: Path, fixture_data) -> None:
    runner = FakeRunner(
        {("node", "--version"): ok("v26.12.1\n"), ("node", "-p"): fail("out of memory")},
        available=["node"],
    )
    findings, sources = runtimes.check_node(context(fixture_data, runner, tmp_path))
    assert ids(findings) == ["ENDPOINT-COMPONENT-CURRENT"]
    assert sources[0].readable is False


def test_certifi_bundle_is_located_and_scanned(tmp_path: Path, fixture_data) -> None:
    bundle = write(
        tmp_path / "site-packages/certifi/cacert.pem", read_fixture_cert("weak-intermediate")
    )
    payload = {"python": "3.12.3", "certifi": "2026.09.01", "where": str(bundle)}
    runner = FakeRunner(
        {("python3", "-c"): ok(json.dumps(payload))},
        available=["python3"],
    )
    ctx = EndpointContext(data=fixture_data, system="linux", env=ENV, runner=runner, fs_root=None)
    findings, sources = runtimes.check_python(ctx)
    assert ids(findings) == ["ENDPOINT-COMPONENT-OUTDATED"]
    assert "2026.10.19" in findings[0].summary
    assert sources[0].count == 1
    assert sources[0].label == "python3 certifi bundle"


def test_missing_certifi_produces_no_finding(tmp_path: Path, fixture_data) -> None:
    payload = {"python": "3.12.3", "error": "ModuleNotFoundError"}
    runner = FakeRunner({("python3", "-c"): ok(json.dumps(payload))}, available=["python3"])
    findings, sources = runtimes.check_python(context(fixture_data, runner, tmp_path))
    assert findings == []
    assert sources == []


def test_java_truststore_is_read_without_a_password(tmp_path: Path, fixture_data) -> None:
    java_home = tmp_path / "usr/lib/jvm/jdk-21"
    cacerts = java_home / "lib/security/cacerts"
    cacerts.parent.mkdir(parents=True)
    cacerts.write_bytes(build_jks([("weak", der_of("weak-intermediate"))]))
    runner = FakeRunner(
        {
            ("java", "-XshowSettings:properties", "-version"): ok(
                'openjdk version "21.0.3" 2024-04-16\n    java.home = %s\n' % java_home
            )
        },
        available=["java"],
    )
    ctx = EndpointContext(data=fixture_data, system="linux", env=ENV, runner=runner, fs_root=None)
    findings, sources = runtimes.check_java(ctx)
    assert ids(findings) == ["ENDPOINT-JAVA-PRESENT"]
    assert sources[0].label == "Java cacerts"
    assert sources[0].count == 1


def test_pkcs12_truststore_is_reported_as_unreadable(tmp_path: Path, fixture_data) -> None:
    java_home = tmp_path / "jdk"
    cacerts = java_home / "lib/security/cacerts"
    cacerts.parent.mkdir(parents=True)
    cacerts.write_bytes(b"\x30\x82\x04\x00" + b"\x00" * 32)
    runner = FakeRunner(
        {("java", "-XshowSettings:properties", "-version"): ok("    java.home = %s\n" % java_home)},
        available=["java"],
    )
    ctx = EndpointContext(data=fixture_data, system="linux", env=ENV, runner=runner, fs_root=None)
    _findings, sources = runtimes.check_java(ctx)
    assert sources[0].readable is False
    assert "pkcs12" in sources[0].detail


def test_git_verification_disabled_is_critical(tmp_path: Path, fixture_data) -> None:
    runner = FakeRunner(
        {("git", "config", "--get", "http.sslVerify"): ok("false\n")},
        available=["git"],
    )
    findings, _sources = runtimes.check_git(context(fixture_data, runner, tmp_path))
    assert ids(findings) == ["ENDPOINT-GIT-VERIFY-DISABLED"]
    assert findings[0].severity == "critical"
    assert model.TAG_VERIFICATION_DISABLED in findings[0].tags


def test_git_custom_ca_bundle_is_scanned(tmp_path: Path, fixture_data) -> None:
    bundle = write(tmp_path / "corp/ca.pem", read_fixture_cert("weak-intermediate"))
    runner = FakeRunner(
        {
            ("git", "config", "--get", "http.sslVerify"): fail("not set"),
            ("git", "config", "--get", "http.sslCAInfo"): ok(str(bundle)),
        },
        available=["git"],
    )
    ctx = EndpointContext(data=fixture_data, system="linux", env=ENV, runner=runner, fs_root=None)
    findings, sources = runtimes.check_git(ctx)
    assert ids(findings) == ["ENDPOINT-GIT-CUSTOM-CA"]
    assert sources[0].role == "override"
    assert sources[0].count == 1


def test_absent_tools_are_simply_not_reported(tmp_path: Path, fixture_data) -> None:
    ctx = context(fixture_data, FakeRunner(available=[]), tmp_path)
    findings, sources = runtimes.audit(ctx)
    assert findings == []
    assert sources == []


def test_client_versions_are_context_not_verdicts(tmp_path: Path, fixture_data) -> None:
    runner = FakeRunner(
        {("curl", "-V"): ok("curl 7.81.0 (x86_64) libcurl/7.81.0 OpenSSL/3.0.2\n")},
        available=["curl"],
    )
    findings = runtimes.check_clients(context(fixture_data, runner, tmp_path))
    assert ids(findings) == ["ENDPOINT-CLIENT-VERSION"]
    assert findings[0].status == model.STATUS_UNABLE
    assert findings[0].severity == "info"
    assert findings[0].action == model.ACTION_NONE
