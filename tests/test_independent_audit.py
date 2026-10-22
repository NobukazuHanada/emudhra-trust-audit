"""Regression cases from the independent security and compatibility audit."""

import json
import os

import pytest

from ca_trust_audit import project
from ca_trust_audit.endpoint import stores
from ca_trust_audit.endpoint.context import EndpointContext
from ca_trust_audit.endpoint.network import split_host
from ca_trust_audit.project import parsers
from ca_trust_audit.project.scan import ProjectContext
from ca_trust_audit.util import read_regular_file
from conftest import FakeRunner, ok, write


@pytest.mark.parametrize(
    "filename,text",
    [
        (".nvmrc", "22.0.0"),
        (".node-version", "22.0.0"),
        (".tool-versions", "nodejs 22.0.0"),
        ("mise.toml", '[tools]\nnode = "22.0.0"'),
        (".go-version", "1.27.0"),
    ],
)
def test_tool_pins_reach_version_policy(tmp_path, fixture_data, filename, text):
    write(tmp_path / filename, text)
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert any(f.id == "PROJECT-DEPENDENCY-OUTDATED" for f in result.findings)


@pytest.mark.parametrize("parser", ["npm-lock", "pipfile-lock", "composer-lock"])
@pytest.mark.parametrize("text", ["[]", "null", '{"default": [], "packages": 123}'])
def test_malformed_json_shapes_are_not_tracebacks(parser, text):
    assert parsers.parse(parser, text) == []


def test_spoofed_indicator_id_does_not_suppress_tls_scan(tmp_path, fixture_data):
    write(
        tmp_path / "config.json",
        json.dumps(
            {
                "ruleset_id": fixture_data.insecure_rules["ruleset_id"],
                "code": "requests.get(url, verify=False)",
            }
        ),
    )
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert any(f.id.startswith("PROJECT-TLS-") for f in result.findings)


def test_reader_rejects_traversal_and_absolute_paths(tmp_path, fixture_data):
    root = tmp_path / "repo"
    root.mkdir()
    outside = write(tmp_path / "secret.txt", "SECRET")
    ctx = ProjectContext(root, fixture_data)
    assert ctx.read_bytes("../secret.txt") is None
    assert ctx.read_bytes(str(outside)) is None


def test_reader_rechecks_links_after_walk(tmp_path, fixture_data):
    root = tmp_path / "repo"
    root.mkdir()
    path = write(root / "client.py", "pass")
    outside = write(tmp_path / "secret", "SECRET")
    ctx = ProjectContext(root, fixture_data)
    ctx.walk()
    path.unlink()
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("symlink privilege unavailable")
    assert ctx.read_text("client.py") is None
    assert ctx.problems


def test_directory_symlink_is_reported(tmp_path, fixture_data):
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symlink privilege unavailable")
    ctx = ProjectContext(root, fixture_data)
    ctx.walk()
    assert "linked directory skipped" in ctx.problems


def test_ignore_file_is_bounded(tmp_path, fixture_data):
    write(tmp_path / ".ca-trust-audit-ignore", "x" * 1_048_577)
    ctx = ProjectContext(tmp_path, fixture_data)
    assert ctx.ignore_patterns == []
    assert ctx.problems


def test_regular_reader_rejects_fifo_without_blocking(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFO support")
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(OSError):
        read_regular_file(path)


def test_windows_no_user_stores_limits_command(fixture_data):
    runner = FakeRunner({("powershell",): ok("")})
    ctx = EndpointContext(
        data=fixture_data, system="windows", runner=runner, include_user_stores=False
    )
    stores.collect_windows_sources(ctx)
    assert "CurrentUser" not in runner.calls[0][-1]
    assert "LocalMachine" in runner.calls[0][-1]


@pytest.mark.parametrize("target", ["host:65536", "host:bad", "-option", "host;echo", "[::1]:0"])
def test_bad_network_targets_rejected_before_connect(target):
    with pytest.raises(ValueError):
        split_host(target)


def test_ipv6_target():
    assert split_host("[::1]:443") == ("::1", 443)


def test_manifest_range_not_mistaken_for_pin():
    deps = parsers.parse_package_json('{"dependencies":{"node":"22.0.0 || 24.0.0"}}')
    assert deps[0].kind == parsers.RANGE


def test_ci_version_cannot_echo_arbitrary_secret(tmp_path, fixture_data):
    write(tmp_path / ".github/workflows/build.yml", "node-version: 22SECRET_SENTINEL")
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert "SECRET_SENTINEL" not in json.dumps(result.to_dict())


def test_unparseable_override_is_coverage_gap(tmp_path, fixture_data):
    from ca_trust_audit.endpoint.env_checks import collect_override_sources

    path = write(tmp_path / "bad.pem", "not a certificate")
    ctx = EndpointContext(data=fixture_data, env={"SSL_CERT_FILE": str(path)})
    _, sources = collect_override_sources(ctx)
    assert sources and not sources[0].readable


def test_curl_insecure_is_not_a_standard_disable_variable(fixture_data):
    from ca_trust_audit.endpoint.env_checks import verification_findings

    ctx = EndpointContext(data=fixture_data, env={"CURL_INSECURE": "1"})
    assert not any(f.id == "ENDPOINT-VERIFICATION-DISABLED-ENV" for f in verification_findings(ctx))


def test_endpoint_default_cannot_open_socket(tmp_path, monkeypatch, capsys):
    import socket

    from ca_trust_audit.cli import main

    def prohibited(*args, **kwargs):
        raise AssertionError("unexpected socket")

    monkeypatch.setattr(socket, "socket", prohibited)
    assert main(["endpoint", "--fs-root", str(tmp_path), "--format", "json"]) in (0, 1, 2)
    json.loads(capsys.readouterr().out)
