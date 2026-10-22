"""Loading, integrity-checking and validating the ``data/`` directory.

Indicators, fixed versions and textual rules live in versioned JSON files, never
in code. They are loaded read-only, their SHA-256 is compared against
``data/checksums.json``, and each file is validated against its schema. Nothing
in this module fetches anything over the network: updating indicators is a
reviewed commit, not a runtime download.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from . import jsonschema_lite

DATA_DIR_ENV = "CA_TRUST_AUDIT_DATA_DIR"

INCIDENT_FILE = "incidents/emudhra-2026.json"
POLICY_FILE = "policies/fixed-versions.json"
INSECURE_RULES_FILE = "rules/insecure-tls.json"
INVENTORY_FILE = "rules/project-inventory.json"
CHECKSUM_FILE = "checksums.json"

_SCHEMA_FOR = {
    INCIDENT_FILE: "schema/incident-v1.json",
    POLICY_FILE: "schema/policy-v1.json",
    INSECURE_RULES_FILE: "schema/ruleset-v1.json",
    INVENTORY_FILE: "schema/ruleset-v1.json",
}

CHECKSUMMED_FILES: Tuple[str, ...] = (
    INCIDENT_FILE,
    POLICY_FILE,
    INSECURE_RULES_FILE,
    INVENTORY_FILE,
    "schema/incident-v1.json",
    "schema/policy-v1.json",
    "schema/ruleset-v1.json",
)


class DataError(RuntimeError):
    """Raised when the data directory is missing, corrupt or invalid."""


def find_data_dir(explicit: Optional[str] = None) -> Path:
    """Locate ``data/``: explicit path, environment variable, then repo layout."""
    candidates: List[Path] = []
    if explicit:
        if not (Path(explicit) / INCIDENT_FILE).is_file():
            raise DataError("explicit data directory is unavailable")
        return Path(explicit).resolve()
    env_value = os.environ.get(DATA_DIR_ENV)
    if env_value:
        candidates.append(Path(env_value))
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(parent / "data")
    candidates.append(Path.cwd() / "data")
    for candidate in candidates:
        if (candidate / INCIDENT_FILE).is_file():
            return candidate.resolve()
    raise DataError("could not locate the data directory; pass --data-dir or set %s" % DATA_DIR_ENV)


def sha256_file(path: Path) -> str:
    """Hash UTF-8 data with LF-normalized newlines; all other bytes matter."""
    digest = hashlib.sha256()
    pending = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            chunk = pending + chunk
            pending = b"\r" if chunk.endswith(b"\r") else b""
            if pending:
                chunk = chunk[:-1]
            digest.update(chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
    if pending:
        digest.update(b"\n")
    return digest.hexdigest()


def compute_checksums(data_dir: Path) -> Dict[str, str]:
    return {name: sha256_file(data_dir / name) for name in CHECKSUMMED_FILES}


def write_checksums(data_dir: Path) -> Path:
    """Maintainer helper: rewrite ``data/checksums.json``.

    This is the only function in the package that writes anything, and it is
    reachable only through ``emudhra-trust-audit data --write-checksums``.
    """
    payload = {
        "schema_version": 1,
        "algorithm": "sha256",
        "normalization": "CRLF and CR line endings normalized to LF; other bytes unchanged",
        "note": (
            "Regenerate with `emudhra-trust-audit data --write-checksums` after editing any "
            "file in data/. Reviewers compare these digests in the pull request."
        ),
        "files": compute_checksums(data_dir),
    }
    target = data_dir / CHECKSUM_FILE
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


@dataclasses.dataclass(frozen=True)
class CompiledRule:
    id: str
    title: str
    regex: Pattern[str]
    status: str
    severity: str
    confidence: str
    description: str
    remediation: Tuple[str, ...]
    references: Tuple[str, ...]
    path_hints: Tuple[str, ...]
    tags: Tuple[str, ...] = ()


@dataclasses.dataclass
class DataBundle:
    data_dir: Path
    incident: Dict[str, Any]
    policy: Dict[str, Any]
    insecure_rules: Dict[str, Any]
    inventory: Dict[str, Any]
    checksum_status: str
    checksum_problems: List[str] = dataclasses.field(default_factory=list)
    schema_problems: List[str] = dataclasses.field(default_factory=list)

    @property
    def compromised_spki(self) -> Dict[str, Dict[str, Any]]:
        return {
            str(entry["spki_sha256"]).lower(): entry
            for entry in self.incident.get("compromised_intermediates", [])
        }

    @property
    def compromised_certificate_sha256(self) -> Dict[str, Dict[str, Any]]:
        return {
            str(value).lower(): {"sha256": value}
            for value in self.incident.get("certificate_sha256", [])
        }

    @property
    def related_root_names(self) -> Dict[str, Dict[str, Any]]:
        return {
            str(entry["common_name"]).lower(): entry
            for entry in self.incident.get("related_roots", [])
        }

    @property
    def incident_references(self) -> List[str]:
        return [str(source["url"]) for source in self.incident.get("sources", [])]

    def compiled_insecure_rules(self) -> List[CompiledRule]:
        compiled: List[CompiledRule] = []
        for rule in self.insecure_rules.get("rules", []):
            flags = 0
            for flag in rule.get("flags", []):
                flags |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}.get(flag, 0)
            compiled.append(
                CompiledRule(
                    id=str(rule["id"]),
                    title=str(rule["title"]),
                    regex=re.compile(str(rule["pattern"]), flags),
                    status=str(rule["status"]),
                    severity=str(rule["severity"]),
                    confidence=str(rule["confidence"]),
                    description=str(rule.get("description", "")),
                    remediation=tuple(rule.get("remediation", [])),
                    references=tuple(rule.get("references", [])),
                    path_hints=tuple(rule.get("path_hints", [])),
                    tags=tuple(rule.get("tags", [])),
                )
            )
        return compiled

    def describe_sources(self) -> List[Dict[str, Any]]:
        described: List[Dict[str, Any]] = []
        for label, payload in (
            ("incident", self.incident),
            ("fixed-versions", self.policy),
            ("insecure-tls-rules", self.insecure_rules),
            ("project-inventory", self.inventory),
        ):
            described.append(
                {
                    "dataset": label,
                    "id": payload.get("policy_id")
                    or payload.get("ruleset_id")
                    or payload.get("incident_id"),
                    "data_version": payload.get("data_version"),
                    "as_of": payload.get("as_of") or payload.get("updated"),
                    "sources": [
                        source["url"] if isinstance(source, dict) else source
                        for source in payload.get("sources", [])
                    ],
                }
            )
        return described


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as error:
        raise DataError("cannot read %s: %s" % (path.name, error)) from error
    except json.JSONDecodeError as error:
        raise DataError("%s is not valid JSON: %s" % (path.name, error)) from error


def load(data_dir: Optional[str] = None, *, validate_schema: bool = True) -> DataBundle:
    """Load and verify every data file. Never touches the network."""
    directory = find_data_dir(data_dir)
    payloads = {name: _load_json(directory / name) for name in _SCHEMA_FOR}

    checksum_problems: List[str] = []
    checksum_path = directory / CHECKSUM_FILE
    if not checksum_path.is_file():
        checksum_status = "absent"
        checksum_problems.append("data/checksums.json is missing")
    else:
        recorded = _load_json(checksum_path).get("files", {})
        actual = compute_checksums(directory)
        for name, digest in sorted(actual.items()):
            expected = recorded.get(name)
            if expected is None:
                checksum_problems.append("%s has no recorded checksum" % name)
            elif expected.lower() != digest:
                checksum_problems.append(
                    "%s digest mismatch: recorded %s, actual %s"
                    % (name, expected[:16], digest[:16])
                )
        for name in sorted(recorded):
            if name not in actual:
                checksum_problems.append("%s is recorded but absent" % name)
        checksum_status = "verified" if not checksum_problems else "mismatch"

    schema_problems: List[str] = []
    if validate_schema:
        for name, schema_name in _SCHEMA_FOR.items():
            schema = _load_json(directory / schema_name)
            schema_problems.extend(
                "%s: %s" % (name, problem)
                for problem in jsonschema_lite.validate(payloads[name], schema)
            )

    return DataBundle(
        data_dir=directory,
        incident=payloads[INCIDENT_FILE],
        policy=payloads[POLICY_FILE],
        insecure_rules=payloads[INSECURE_RULES_FILE],
        inventory=payloads[INVENTORY_FILE],
        checksum_status=checksum_status,
        checksum_problems=checksum_problems,
        schema_problems=schema_problems,
    )
