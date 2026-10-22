from __future__ import annotations

import pytest

from ca_trust_audit import versions


@pytest.mark.parametrize(
    "left,right,expected",
    [
        # Values checked against `dpkg --compare-versions` on a Debian system.
        ("20250419~deb12u1", "20250419~deb12u2", -1),
        ("20250419~deb12u2", "20250419~deb12u2", 0),
        ("20250419~deb12u2", "20250419", -1),  # '~' sorts before everything
        ("20250419", "20250419+deb13u1", -1),
        ("20260816ubuntu0.24.04.1", "20260816", 1),
        ("20240203", "20260816", -1),
        ("3.131.0-1", "3.131.1-1", -1),
        ("20261019-r0", "20261020-r0", -1),
        ("1:1.0-1", "2:0.9-1", -1),  # epoch wins
        ("2026.2.92_v9.0.319", "2026.2.93_v9.0.320", -1),
    ],
)
def test_dpkg_ordering(left: str, right: str, expected: int) -> None:
    assert versions.compare_dpkg(left, right) == expected
    assert versions.compare_dpkg(right, left) == -expected


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("2026.10.19", "2026.10.19", 0),
        ("2026.09.01", "2026.10.19", -1),
        ("0.13.4", "0.13.10", -1),
        ("24.22.1", "24.9.0", 1),
        ("v22.23.4", "22.23.4", 0),
        ("1.2.3", "1.2.3-rc1", 1),  # a release outranks its pre-release
        ("1.27.3", "1.27", 1),
    ],
)
def test_generic_ordering(left: str, right: str, expected: int) -> None:
    assert versions.compare_generic(left, right) == expected
    assert versions.compare_generic(right, left) == -expected


def test_evaluate_reports_unknown_rather_than_guessing() -> None:
    assert versions.evaluate("2026.10.19", "2026.10.19") == versions.OK
    assert versions.evaluate("2026.09.01", "2026.10.19") == versions.OUTDATED
    assert versions.evaluate("2026.10.19", None) == versions.UNKNOWN
    assert versions.evaluate("", "2026.10.19") == versions.UNKNOWN
    assert versions.evaluate("not-a-version", "2026.10.19") == versions.UNKNOWN
    assert versions.evaluate("2026.10.19", "unknown") == versions.UNKNOWN


def test_branch_scope_does_not_leak_across_release_lines() -> None:
    branches = [{"match": "22", "fixed": "22.23.4"}, {"match": "24", "fixed": "24.22.1"}]
    assert versions.branch_of("22.1.0", branches)["fixed"] == "22.23.4"
    assert versions.branch_of("24.0.0", branches)["fixed"] == "24.22.1"
    # Node 20 is covered by no branch: silence, not a verdict.
    assert versions.branch_of("20.11.0", branches) is None
    # A prefix must be followed by a dot, so 2.2 never matches branch '2'.
    assert versions.branch_of("220.0.0", branches) is None


def test_wildcard_branch_matches_anything() -> None:
    branches = [{"match": "*", "fixed": "2026.10.19"}]
    assert versions.branch_of("1999.1.1", branches)["fixed"] == "2026.10.19"


@pytest.mark.parametrize(
    "text,expected",
    [
        ("go version go1.27.3 linux/amd64", "1.27.3"),
        ("v24.22.1", "24.22.1"),
        ("curl 8.5.0 (x86_64-pc-linux-gnu)", "8.5.0"),
        ("pip 26.2.2 from /usr/lib/python3/dist-packages/pip (python 3.12)", "26.2.2"),
        ("no version here", ""),
        ("", ""),
    ],
)
def test_extract_version(text: str, expected: str) -> None:
    assert versions.extract_version(text) == expected
