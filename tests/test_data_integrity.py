"""The shipped indicator data must be verifiable, sourced and dated."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ca_trust_audit import datafiles, jsonschema_lite
from conftest import REPO_ROOT

HEX64 = re.compile(r"^[0-9A-Fa-f]{64}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def test_checksums_match_the_files_on_disk(real_data: datafiles.DataBundle) -> None:
    assert real_data.checksum_status == "verified", real_data.checksum_problems


def test_every_file_validates_against_its_schema(real_data: datafiles.DataBundle) -> None:
    assert real_data.schema_problems == []


def test_tampering_with_a_data_file_is_detected(tmp_path: Path) -> None:
    import shutil

    data_dir = tmp_path / "data"
    shutil.copytree(REPO_ROOT / "data", data_dir)
    target = data_dir / datafiles.INCIDENT_FILE
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["compromised_intermediates"][0]["spki_sha256"] = "0" * 64
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    bundle = datafiles.load(str(data_dir))
    assert bundle.checksum_status == "mismatch"
    assert any("emudhra-2026.json" in problem for problem in bundle.checksum_problems)


def test_indicator_shape(real_data: datafiles.DataBundle) -> None:
    incident = real_data.incident
    intermediates = incident["compromised_intermediates"]
    assert len(intermediates) == 8
    for entry in intermediates:
        assert HEX64.match(entry["spki_sha256"]), entry
        assert entry["usage"] in ("tls", "code-signing")
        assert entry["common_name"]
    assert len({entry["spki_sha256"].lower() for entry in intermediates}) == 8
    assert sum(1 for entry in intermediates if entry["usage"] == "tls") == 6
    assert sum(1 for entry in intermediates if entry["usage"] == "code-signing") == 2
    # 8 keys x 2 signing paths; the derivation is recorded alongside the number.
    assert incident["certificate_count_expected"] == 16
    assert incident["is_malware_incident"] is False
    assert incident["primary_match_key"] == "spki_sha256"
    assert incident["root_presence_is_not_an_indicator"] is True


def test_certificate_fingerprints_are_absent_but_explained(real_data: datafiles.DataBundle) -> None:
    incident = real_data.incident
    assert incident["certificate_sha256"] == []
    assert incident["certificate_sha256_status"] == "not-transcribed"
    assert "redistribution" in incident["certificate_sha256_note"].lower()


def test_every_dataset_carries_sources_and_dates(real_data: datafiles.DataBundle) -> None:
    for payload in (
        real_data.incident,
        real_data.policy,
        real_data.insecure_rules,
        real_data.inventory,
    ):
        assert payload["data_version"]
        assert payload["schema_version"] == 1
        sources = payload.get("sources", [])
        assert sources, payload.get("ruleset_id") or payload.get("policy_id")
        for source in sources:
            assert source["url"].startswith("https://")
            assert DATE.match(source["retrieved"])
            assert source["used_for"]


def test_policy_entries_are_dated_and_sourced(real_data: datafiles.DataBundle) -> None:
    for entry in real_data.policy["os_ca_bundles"] + real_data.policy["packages"]:
        assert DATE.match(entry["as_of"])
        assert entry["sources"]
        assert all(url.startswith("https://") for url in entry["sources"])


def test_credential_guidance_is_conditional(real_data: datafiles.DataBundle) -> None:
    guidance = real_data.incident["credential_guidance"]
    states = {condition["state"] for condition in guidance["conditions"]}
    assert states == {"CREDENTIAL_REVIEW_REQUIRED", "CREDENTIAL_ACTION_REQUIRED", "ESCALATE"}
    assert guidance["sources"]
    # The weakest evidence must lead to a review, not to a blanket rotation.
    review = next(c for c in guidance["conditions"] if c["state"] == "CREDENTIAL_REVIEW_REQUIRED")
    assert any("not rotate everything" in step.lower() for step in review["do"])
    assert guidance["principle"].lower().startswith("a weak ca key creates the capability")


def test_rules_compile_and_have_unique_ids(real_data: datafiles.DataBundle) -> None:
    rules = real_data.compiled_insecure_rules()
    assert len(rules) == len(real_data.insecure_rules["rules"])
    assert len({rule.id for rule in rules}) == len(rules)
    for rule in rules:
        assert rule.remediation, rule.id
        assert rule.status in ("known_indicator", "suspicious")
        assert rule.severity in ("critical", "high", "medium", "low", "info", "pass")


def test_related_roots_include_the_cross_signing_root(real_data: datafiles.DataBundle) -> None:
    names = real_data.related_root_names
    assert "aaa certificate services" in names
    assert "note" in names["aaa certificate services"]
    assert len(names) == 4


def test_schema_validator_rejects_a_broken_record() -> None:
    schema = json.loads(
        (REPO_ROOT / "data" / "schema" / "incident-v1.json").read_text(encoding="utf-8")
    )
    errors = jsonschema_lite.validate({"schema_version": 2}, schema)
    assert any("schema_version" in error for error in errors)
    assert any("missing required property" in error for error in errors)


@pytest.mark.parametrize("name", list(datafiles.CHECKSUMMED_FILES))
def test_checksummed_files_exist(name: str) -> None:
    assert (REPO_ROOT / "data" / name).is_file()
