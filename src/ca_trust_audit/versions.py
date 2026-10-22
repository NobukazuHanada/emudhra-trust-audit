"""Version comparison for the fixed-version policy.

Two schemes are supported:

``dpkg``     the Debian algorithm, which is also close enough for rpm, pacman
             and apk version strings (``~`` sorts before everything, digit runs
             compare numerically, letters sort before other characters).
``generic``  dotted numeric versions with an optional pre-release suffix, which
             covers semver, CalVer and the ``1.27.3`` style of Go releases.

A version that cannot be parsed, or that falls in no policy branch, yields
``UNKNOWN`` - never ``OK``. Guessing "probably fine" is the failure mode this
module exists to avoid.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

OK = "ok"
OUTDATED = "outdated"
UNKNOWN = "unknown"

_VERSION_IN_TEXT = re.compile(r"(\d+(?:\.\d+)+(?:[-+~][0-9A-Za-z.~+_-]+)?)")


def normalize(version: str) -> str:
    version = (version or "").strip()
    if version[:1] in ("v", "V") and version[1:2].isdigit():
        version = version[1:]
    return version


def extract_version(text: str) -> str:
    """Pull the first dotted version out of command output such as ``go1.27.3``."""
    if not text:
        return ""
    match = _VERSION_IN_TEXT.search(text)
    return match.group(1) if match else ""


def _dpkg_order(char: str) -> int:
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def _compare_dpkg_part(left: str, right: str) -> int:
    i = j = 0
    while i < len(left) or j < len(right):
        first_diff = 0
        while (i < len(left) and not left[i].isdigit()) or (
            j < len(right) and not right[j].isdigit()
        ):
            left_char = left[i] if i < len(left) else ""
            right_char = right[j] if j < len(right) else ""
            left_order = _dpkg_order(left_char) if left_char else 0
            right_order = _dpkg_order(right_char) if right_char else 0
            if left_order != right_order:
                return -1 if left_order < right_order else 1
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        while i < len(left) and left[i].isdigit() and j < len(right) and right[j].isdigit():
            if first_diff == 0:
                first_diff = (left[i] > right[j]) - (left[i] < right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_dpkg(version: str) -> Tuple[int, str, str]:
    epoch = 0
    rest = version
    if ":" in rest:
        head, _, tail = rest.partition(":")
        if head.isdigit():
            epoch = int(head)
            rest = tail
    if "-" in rest:
        upstream, _, revision = rest.rpartition("-")
    else:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def compare_dpkg(left: str, right: str) -> int:
    left_epoch, left_up, left_rev = _split_dpkg(normalize(left))
    right_epoch, right_up, right_rev = _split_dpkg(normalize(right))
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    result = _compare_dpkg_part(left_up, right_up)
    if result:
        return result
    return _compare_dpkg_part(left_rev, right_rev)


def _tokenize_generic(version: str) -> List[object]:
    tokens: List[object] = []
    for chunk in re.split(r"[^0-9A-Za-z]+", version):
        if not chunk:
            continue
        for part in re.findall(r"\d+|[A-Za-z]+", chunk):
            tokens.append(int(part) if part.isdigit() else part.lower())
    return tokens


def compare_generic(left: str, right: str) -> int:
    left_tokens = _tokenize_generic(normalize(left))
    right_tokens = _tokenize_generic(normalize(right))
    for index in range(max(len(left_tokens), len(right_tokens))):
        lhs = left_tokens[index] if index < len(left_tokens) else 0
        rhs = right_tokens[index] if index < len(right_tokens) else 0
        if isinstance(lhs, int) and isinstance(rhs, int):
            if lhs != rhs:
                return -1 if lhs < rhs else 1
            continue
        if isinstance(lhs, int) != isinstance(rhs, int):
            # A numeric component outranks an alphabetic one, so 1.2.3 sorts
            # above the pre-release 1.2.3-rc1.
            return 1 if isinstance(lhs, int) else -1
        if lhs != rhs:
            return -1 if str(lhs) < str(rhs) else 1
    return 0


def compare(left: str, right: str, scheme: str = "generic") -> int:
    if scheme == "dpkg":
        return compare_dpkg(left, right)
    return compare_generic(left, right)


def is_parseable(version: str, scheme: str = "generic") -> bool:
    version = normalize(version)
    if not version:
        return False
    if scheme == "dpkg":
        return bool(re.match(r"^[0-9]", version))
    return bool(re.match(r"^\d+(\.\d+)*", version))


def evaluate(installed: str, fixed: Optional[str], scheme: str = "generic") -> str:
    """``OK`` when installed >= fixed, ``OUTDATED`` when below, else ``UNKNOWN``."""
    if not fixed:
        return UNKNOWN
    if not is_parseable(installed, scheme) or not is_parseable(fixed, scheme):
        return UNKNOWN
    return OK if compare(installed, fixed, scheme) >= 0 else OUTDATED


def branch_of(version: str, branches: Sequence[dict]) -> Optional[dict]:
    """Select the policy branch that covers ``version``.

    A branch whose ``match`` is ``*`` covers everything. Otherwise the installed
    version must equal the branch prefix or continue it with a dot, so a policy
    for Node 22 never speaks for Node 20.
    """
    version = normalize(version)
    wildcard: Optional[dict] = None
    for branch in branches:
        match = str(branch.get("match", ""))
        if match == "*":
            wildcard = wildcard or branch
            continue
        if version == match or version.startswith(match + "."):
            return branch
    return wildcard
