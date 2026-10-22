"""macOS and Windows paths, driven by recorded command output.

These platform branches cannot be executed on a Linux CI runner, so the
commands are replayed from recorded output. The parsing, matching and
reporting logic is the real implementation.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import List

from ca_trust_audit import model
from ca_trust_audit.endpoint import stores
from ca_trust_audit.endpoint.context import EndpointContext
from conftest import FakeRunner, fail, ok, read_fixture_cert, write

DARWIN_ENV = {"HOME": "/Users/tester", "USER": "tester", "PATH": "/usr/bin"}


def der_b64(name: str) -> str:
    body = read_fixture_cert(name).split("-----")[2]
    return "".join(body.split())


def ids(findings: List[model.Finding]) -> List[str]:
    return [finding.id for finding in findings]


def test_darwin_keychain_dump_is_parsed_and_matched(tmp_path: Path, fixture_data) -> None:
    fs_root = tmp_path / "fsroot"
    write(fs_root / "System/Library/Keychains/SystemRootCertificates.keychain", "binary keychain")
    runner = FakeRunner(
        {
            (
                "security",
                "find-certificate",
                "-a",
                "-p",
                "/System/Library/Keychains/SystemRootCertificates.keychain",
            ): ok(read_fixture_cert("unrelated") + read_fixture_cert("weak-intermediate"))
        },
        available=["security"],
    )
    ctx = EndpointContext(
        data=fixture_data, system="darwin", env=DARWIN_ENV, runner=runner, fs_root=fs_root
    )
    sources = stores.collect_darwin_sources(ctx)
    assert len(sources) == 1
    assert sources[0].count == 2

    findings = stores.evaluate_sources(ctx, sources)
    finding = next(f for f in findings if f.id == "ENDPOINT-SPKI-TRUSTED")
    assert finding.status == model.STATUS_KNOWN_INDICATOR
    assert "System Roots keychain" in " ".join(item.what for item in finding.evidence)


def test_darwin_keychain_failure_is_unable_to_assess(tmp_path: Path, fixture_data) -> None:
    fs_root = tmp_path / "fsroot"
    write(fs_root / "System/Library/Keychains/SystemRootCertificates.keychain", "binary keychain")
    runner = FakeRunner(
        {("security",): fail("SecKeychainCopySearchList failed")}, available=["security"]
    )
    ctx = EndpointContext(
        data=fixture_data, system="darwin", env=DARWIN_ENV, runner=runner, fs_root=fs_root
    )
    sources = stores.collect_darwin_sources(ctx)
    assert sources[0].readable is False

    findings = stores.evaluate_sources(ctx, sources)
    assert "ENDPOINT-STORE-UNREADABLE" in ids(findings)
    assert "ENDPOINT-SPKI-ABSENT" not in ids(findings)


def test_darwin_cli_bundle_is_a_separate_trust_source(tmp_path: Path, fixture_data) -> None:
    """Safari being fine says nothing about /etc/ssl/cert.pem, which curl uses."""
    fs_root = tmp_path / "fsroot"
    write(fs_root / "etc/ssl/cert.pem", read_fixture_cert("weak-intermediate"))
    ctx = EndpointContext(
        data=fixture_data, system="darwin", env=DARWIN_ENV, runner=FakeRunner(), fs_root=fs_root
    )
    sources = stores.collect_darwin_sources(ctx)
    assert [source.label for source in sources] == [
        "OpenSSL/LibreSSL cert.pem used by command line clients"
    ]
    findings = stores.evaluate_sources(ctx, sources)
    assert "ENDPOINT-SPKI-TRUSTED" in ids(findings)


def test_windows_disallowed_store_means_blocked(fixture_data) -> None:
    output = "\n".join(
        [
            "Cert:\\LocalMachine\\Root|" + der_b64("unrelated"),
            "Cert:\\LocalMachine\\Disallowed|" + der_b64("weak-intermediate"),
        ]
    )
    runner = FakeRunner({("powershell",): ok(output)}, available=["powershell"])
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    sources = stores.collect_windows_sources(ctx)
    roles = {source.label: source.role for source in sources}
    assert roles["Windows store Cert:\\LocalMachine\\Disallowed"] == stores.ROLE_DISTRUSTED
    assert roles["Windows store Cert:\\LocalMachine\\Root"] == stores.ROLE_TRUSTED

    findings = stores.evaluate_sources(ctx, sources)
    assert "ENDPOINT-SPKI-DISTRUSTED" in ids(findings)
    assert "ENDPOINT-SPKI-TRUSTED" not in ids(findings)


def test_windows_root_store_membership_means_exposed(fixture_data) -> None:
    output = "Cert:\\LocalMachine\\Root|" + der_b64("weak-intermediate")
    runner = FakeRunner({("powershell",): ok(output)}, available=["powershell"])
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    findings = stores.evaluate_sources(ctx, stores.collect_windows_sources(ctx))
    assert "ENDPOINT-SPKI-TRUSTED" in ids(findings)


def test_windows_store_enumeration_failure_is_unable_to_assess(fixture_data) -> None:
    runner = FakeRunner({("powershell",): fail("access denied")}, available=["powershell"])
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    sources = stores.collect_windows_sources(ctx)
    assert sources[0].readable is False
    findings = stores.evaluate_sources(ctx, sources)
    assert "ENDPOINT-STORE-UNREADABLE" in ids(findings)


def test_windows_garbage_lines_are_skipped(fixture_data) -> None:
    output = "\n".join(
        [
            "not-a-line",
            "Cert:\\LocalMachine\\Root|%%%not-base64%%%",
            "Cert:\\LocalMachine\\Root|" + base64.b64encode(b"\x30\x03\x02\x01\x00").decode(),
            "Cert:\\LocalMachine\\Root|" + der_b64("unrelated"),
        ]
    )
    runner = FakeRunner({("powershell",): ok(output)}, available=["powershell"])
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    sources = stores.collect_windows_sources(ctx)
    assert sum(source.count for source in sources) == 1


def test_windows_auto_update_policy_disabled(fixture_data) -> None:
    runner = FakeRunner(
        {("powershell",): ok("DisableRootAutoUpdate=1\nDisallowedCtlPresent=False\n")},
        available=["powershell"],
    )
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    findings = stores.windows_root_update_findings(ctx)
    assert ids(findings) == ["ENDPOINT-WINDOWS-CTL-DISABLED"]
    assert findings[0].action == model.ACTION_REQUIRED
    assert any("change control" in step for step in findings[0].remediation)


def test_windows_auto_update_policy_enabled(fixture_data) -> None:
    runner = FakeRunner(
        {("powershell",): ok("DisableRootAutoUpdate=\nDisallowedCtlPresent=True\n")},
        available=["powershell"],
    )
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    findings = stores.windows_root_update_findings(ctx)
    assert ids(findings) == ["ENDPOINT-WINDOWS-CTL-ENABLED"]
    assert findings[0].severity == "pass"
    assert "does not prove" in findings[0].summary


def test_windows_policy_query_failure(fixture_data) -> None:
    runner = FakeRunner({("powershell",): fail("no such key")}, available=["powershell"])
    ctx = EndpointContext(
        data=fixture_data, system="windows", env={}, runner=runner, fs_root=Path("/")
    )
    findings = stores.windows_root_update_findings(ctx)
    assert ids(findings) == ["ENDPOINT-WINDOWS-CTL-UNKNOWN"]
    assert findings[0].status == model.STATUS_UNABLE
