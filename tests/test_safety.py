from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from ca_trust_audit import certs, model, project
from ca_trust_audit.cli import main
from ca_trust_audit.endpoint import stores
from ca_trust_audit.endpoint.context import EndpointContext
from ca_trust_audit.project.scan import ProjectContext
from conftest import REPO_ROOT, read_fixture_cert, write


def test_source_line_with_secret_never_reaches_any_renderer(tmp_path, fixture_data):
    from ca_trust_audit import report as rendering

    write(
        tmp_path / "client.py",
        'requests.get("https://example.test", verify=False, headers={"Authorization": "SECRET_SENTINEL"})',
    )
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    for fmt in ("json", "text", "sarif"):
        assert "SECRET_SENTINEL" not in rendering.render(result, fmt)
    assert any(f.id.startswith("PROJECT-TLS-") for f in result.findings)


def test_os_blocklist_does_not_suppress_independent_bundle(fixture_data):
    certificate = certs.parse_bundle(read_fixture_cert("weak-intermediate").encode())
    sources = [
        stores.TrustSource("Windows Disallowed", "store", stores.ROLE_DISTRUSTED, certificate),
        stores.TrustSource("certifi", "bundle", stores.ROLE_INDEPENDENT, certificate),
    ]
    findings = stores.evaluate_sources(EndpointContext(data=fixture_data), sources)
    assert any(
        f.id == "ENDPOINT-SPKI-TRUSTED" and f.action == model.ACTION_REQUIRED for f in findings
    )
    assert any(f.id == "ENDPOINT-SPKI-DISTRUSTED" for f in findings)
    report = model.Report("test", "0", "test", "", findings=findings)
    assert report.verdict == model.VERDICT_UNKNOWN


def test_all_pinned_versions_checked(tmp_path, fixture_data):
    write(tmp_path / "one/requirements.txt", "certifi==2026.10.19\n")
    write(tmp_path / "two/requirements.txt", "certifi==2024.1.1\n")
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert any(
        f.id == "PROJECT-DEPENDENCY-OUTDATED" and f.locations == ["two/requirements.txt"]
        for f in result.findings
    )


def test_unsupported_lockfile_is_not_a_pass(tmp_path, fixture_data):
    write(tmp_path / "bun.lockb", "opaque")
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert any(
        f.status == model.STATUS_UNABLE and f.action == model.ACTION_REVIEW for f in result.findings
    )


def test_project_default_is_offline_read_only(tmp_path, monkeypatch, capsys):
    import socket

    def prohibited(*args, **kwargs):
        raise AssertionError("unexpected process or network")

    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(subprocess, "run", prohibited)
    write(tmp_path / "package.json", '{"name": "test"}')
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert main(["project", str(tmp_path), "--format", "json"]) in (0, 1, 2)
    json.loads(capsys.readouterr().out)
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


def test_endpoint_default_executes_no_program(tmp_path, monkeypatch, capsys):
    def prohibited(*args, **kwargs):
        raise AssertionError("unexpected subprocess")

    monkeypatch.setattr(subprocess, "run", prohibited)
    assert main(["endpoint", "--fs-root", str(tmp_path), "--format", "json"]) in (0, 1, 2)
    result = json.loads(capsys.readouterr().out)
    assert result["context"]["commands"] == "disabled"


@pytest.mark.parametrize(
    "args",
    [
        ["project", "ABSENT_SECRET_PATH", "--format", "json"],
        ["endpoint", "--data-dir", "ABSENT_SECRET_PATH", "--format", "json"],
        ["project", "--invalid-SECRET"],
    ],
)
def test_errors_are_json_without_input_disclosure(args, capsys):
    assert main(args) == 3
    captured = capsys.readouterr()
    assert "SECRET" not in captured.out + captured.err
    assert json.loads(captured.out)["exit_code"] == 3


@pytest.mark.parametrize("crlf", [False, True])
def test_portable_skills_work_without_checkout(tmp_path, crlf):
    build = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/build_skills.py"), str(tmp_path / "build")],
        capture_output=True,
    )
    assert build.returncode == 0
    for name in ("endpoint-trust-audit", "project-trust-audit"):
        standalone = tmp_path / name
        shutil.copytree(tmp_path / "build" / name, standalone)
        if crlf:
            for path in (standalone / "scripts" / "data").rglob("*.json"):
                path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        before = {
            p.relative_to(standalone): p.read_bytes() for p in standalone.rglob("*") if p.is_file()
        }
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(standalone / "run.py"),
                "data",
                "--verify",
                "--format",
                "json",
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["checksum_status"] == "verified"
        assert before == {
            p.relative_to(standalone): p.read_bytes() for p in standalone.rglob("*") if p.is_file()
        }


def test_invalid_lockfile_is_unable_to_assess(tmp_path, fixture_data):
    write(tmp_path / "package-lock.json", "{broken json")
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert any(
        f.id == "PROJECT-SCAN-TRUNCATED" and f.status == model.STATUS_UNABLE
        for f in result.findings
    )


def test_dependency_url_secret_is_withheld(tmp_path, fixture_data):
    write(
        tmp_path / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "node_modules/@anthropic-ai/claude-code": {
                        "version": "https://user:SECRET_SENTINEL@example.test/pkg"
                    }
                }
            }
        ),
    )
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert "SECRET_SENTINEL" not in json.dumps(result.to_dict())


def test_oversized_file_reports_coverage_gap(tmp_path, fixture_data):
    write(tmp_path / "client.py", "x" * 1_048_577)
    result = project.audit(ProjectContext(tmp_path, fixture_data))
    assert any(
        f.id == "PROJECT-SCAN-TRUNCATED" and f.action == model.ACTION_REVIEW
        for f in result.findings
    )
