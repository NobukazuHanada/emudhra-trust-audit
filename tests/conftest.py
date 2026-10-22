"""Shared fixtures.

The indicator data used by the tests is a *copy* of the real ``data/`` directory
with the eight production SPKIs replaced by the SPKI of a locally generated test
certificate. That way the end-to-end matching path - parse, hash, compare,
report - is exercised for real, without shipping or depending on any third-party
certificate.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import pytest

from ca_trust_audit import certs, datafiles
from ca_trust_audit.util import CommandResult, CommandRunner

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CERTS = Path(__file__).resolve().parent / "fixtures" / "certs"


def read_fixture_cert(name: str) -> str:
    return (FIXTURE_CERTS / ("%s.pem" % name)).read_text(encoding="utf-8")


def fixture_spki(name: str) -> str:
    parsed = certs.parse_bundle(read_fixture_cert(name).encode("utf-8"))
    assert parsed, "fixture certificate %s did not parse" % name
    return parsed[0].spki_sha256


class FakeRunner(CommandRunner):
    """A CommandRunner that replays recorded output instead of executing."""

    def __init__(
        self,
        responses: Optional[Dict[Tuple[str, ...], CommandResult]] = None,
        *,
        available: Optional[Sequence[str]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(env=env or {}, enabled=True)
        self.responses = dict(responses or {})
        self.available = set(available or [])
        self.calls: List[List[str]] = []

    def which(self, program: str) -> Optional[str]:
        return "/usr/bin/%s" % program if program in self.available else None

    def run(self, argv: Sequence[str], timeout: int = 20) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        for key, result in self.responses.items():
            if tuple(argv[: len(key)]) == key:
                return result
        return CommandResult(argv=argv, error="no recorded response")


def ok(stdout: str) -> CommandResult:
    return CommandResult(argv=["recorded"], returncode=0, stdout=stdout)


def fail(message: str = "boom") -> CommandResult:
    return CommandResult(argv=["recorded"], returncode=1, stderr=message)


@pytest.fixture(scope="session")
def real_data() -> datafiles.DataBundle:
    return datafiles.load(str(REPO_ROOT / "data"))


@pytest.fixture
def fixture_data(tmp_path: Path) -> datafiles.DataBundle:
    """Real data files with the indicator list swapped for fixture values."""
    data_dir = tmp_path / "data"
    shutil.copytree(REPO_ROOT / "data", data_dir)

    incident_path = data_dir / datafiles.INCIDENT_FILE
    incident = json.loads(incident_path.read_text(encoding="utf-8"))
    incident["compromised_intermediates"] = [
        {
            "common_name": "Fixture Weak Intermediate CA - T1",
            "usage": "tls",
            "spki_sha256": fixture_spki("weak-intermediate").upper(),
            "signing_paths": ["fixture-direct"],
        }
    ]
    incident["related_roots"] = [
        {"common_name": "Fixture Related Root CA - T0", "role": "fixture-root"}
    ]
    incident_path.write_text(json.dumps(incident, indent=2) + "\n", encoding="utf-8")

    datafiles.write_checksums(data_dir)
    bundle = datafiles.load(str(data_dir))
    assert bundle.checksum_status == "verified"
    assert not bundle.schema_problems
    return bundle


@pytest.fixture
def fs_root(tmp_path: Path) -> Path:
    root = tmp_path / "fsroot"
    (root / "etc" / "ssl" / "certs").mkdir(parents=True)
    return root


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
