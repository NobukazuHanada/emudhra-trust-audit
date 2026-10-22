"""Lock file and manifest parsing, without resolving anything.

Each parser reads text that is already on disk and returns the pinned versions it
can state with confidence. Nothing is installed, downloaded or resolved, and a
version range is reported as a range rather than guessed into a concrete
version.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Dict, List, Optional

PINNED = "pinned"
RANGE = "range"


@dataclasses.dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    kind: str = PINNED
    file: str = ""
    parser: str = ""

    @property
    def normalized(self) -> str:
        return self.name.strip().lower()


def _dep(
    name: str, version: str, ecosystem: str, file: str, parser: str, kind: str = PINNED
) -> Dependency:
    return Dependency(
        name=name.strip(),
        version=(
            version.strip()
            if re.fullmatch(r"[0-9vVxX*~^<>=!|.,+_ /-]{1,160}", version.strip())
            else "<unresolved>"
        ),
        ecosystem=ecosystem,
        kind=kind,
        file=file,
        parser=parser,
    )


def parse_npm_lock(text: str, *, file: str = "") -> List[Dependency]:
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return []
    except (json.JSONDecodeError, RecursionError):
        return []
    out: List[Dependency] = []

    def walk_v1(mapping: Dict[str, object]) -> None:
        for name, entry in mapping.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str):
                out.append(_dep(name, version, "npm", file, "npm-lock"))
            nested = entry.get("dependencies")
            if isinstance(nested, dict) and len(out) < 20000:
                walk_v1(nested)

    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path, entry in packages.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if not isinstance(version, str):
                continue
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                name = path.split("node_modules/")[-1] if path else ""
            if name:
                out.append(_dep(name, version, "npm", file, "npm-lock"))
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict) and not isinstance(packages, dict):
        walk_v1(dependencies)
    return out


_YARN_ENTRY = re.compile(r'^(?P<header>"?[^\s#].*?:)\n(?P<body>(?:[ \t]+.*\n?)*)', re.MULTILINE)
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?(?P<version>[^"\s]+)"?', re.MULTILINE)


def parse_yarn_lock(text: str, *, file: str = "") -> List[Dependency]:
    out: List[Dependency] = []
    for match in _YARN_ENTRY.finditer(text):
        header = match.group("header").strip().rstrip(":")
        version_match = _YARN_VERSION.search(match.group("body"))
        if not version_match:
            continue
        version = version_match.group("version")
        for spec in header.split(","):
            spec = spec.strip().strip('"')
            if "@" not in spec:
                continue
            name = spec[: spec.rindex("@")]
            if name:
                out.append(_dep(name, version, "npm", file, "yarn-lock"))
                break
    return out


_PNPM_PACKAGE = re.compile(
    r"^\s{2,}['\"]?/?(?P<name>(?:@[^/'\"@\s]+/)?[^/'\"@\s]+)[/@](?P<version>\d[^('\":\s]*)",
    re.MULTILINE,
)


def parse_pnpm_lock(text: str, *, file: str = "") -> List[Dependency]:
    out: List[Dependency] = []
    for match in _PNPM_PACKAGE.finditer(text):
        out.append(_dep(match.group("name"), match.group("version"), "npm", file, "pnpm-lock"))
    return out


_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*(?P<op>==|===|~=|>=)\s*(?P<version>[^\s;#\\]+)"
)


def parse_requirements(text: str, *, file: str = "") -> List[Dependency]:
    out: List[Dependency] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("#", "-")):
            continue
        match = _REQUIREMENT.match(line)
        if not match:
            continue
        kind = PINNED if match.group("op") in ("==", "===") else RANGE
        out.append(
            _dep(match.group("name"), match.group("version"), "pypi", file, "requirements", kind)
        )
    return out


_TOML_PACKAGE_BLOCK = re.compile(r"\[\[package\]\](?P<body>(?:(?!\n\[).)*)", re.DOTALL)
_TOML_FIELD = re.compile(r'^\s*(?P<key>name|version)\s*=\s*"(?P<value>[^"]*)"', re.MULTILINE)


def parse_toml_lock(text: str, *, file: str = "", ecosystem: str = "") -> List[Dependency]:
    """Cargo.lock, poetry.lock, uv.lock and pdm.lock share the [[package]] shape."""
    guessed = ecosystem or ("crates" if "Cargo" in file else "pypi")
    out: List[Dependency] = []
    for block in _TOML_PACKAGE_BLOCK.finditer(text):
        fields = {
            m.group("key"): m.group("value") for m in _TOML_FIELD.finditer(block.group("body"))
        }
        if fields.get("name") and fields.get("version"):
            out.append(_dep(fields["name"], fields["version"], guessed, file, "toml-lock"))
    return out


def parse_composer_lock(text: str, *, file: str = "") -> List[Dependency]:
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return []
    except (json.JSONDecodeError, RecursionError):
        return []
    out: List[Dependency] = []
    for section in ("packages", "packages-dev"):
        for entry in payload.get(section, []) or []:
            if isinstance(entry, dict) and entry.get("name") and entry.get("version"):
                out.append(
                    _dep(
                        str(entry["name"]),
                        str(entry["version"]),
                        "packagist",
                        file,
                        "composer-lock",
                    )
                )
    return out


def parse_pipfile_lock(text: str, *, file: str = "") -> List[Dependency]:
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return []
    except (json.JSONDecodeError, RecursionError):
        return []
    out: List[Dependency] = []
    for section in ("default", "develop"):
        mapping = payload.get(section) or {}
        if not isinstance(mapping, dict):
            continue
        for name, entry in mapping.items():
            if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                version = entry["version"].lstrip("=")
                out.append(_dep(name, version, "pypi", file, "pipfile-lock"))
    return out


_GEMFILE_ENTRY = re.compile(
    r"^\s{4}(?P<name>[A-Za-z0-9._-]+) \((?P<version>[^)]+)\)$", re.MULTILINE
)


def parse_gemfile_lock(text: str, *, file: str = "") -> List[Dependency]:
    return [
        _dep(match.group("name"), match.group("version"), "rubygems", file, "gemfile-lock")
        for match in _GEMFILE_ENTRY.finditer(text)
    ]


_GOSUM_LINE = re.compile(r"^(?P<name>\S+)\s+v(?P<version>[^\s/]+)(?:/go\.mod)?\s+h1:", re.MULTILINE)
_GOMOD_GO = re.compile(r"^go\s+(?P<version>\d+\.\d+(?:\.\d+)?)", re.MULTILINE)
_GOMOD_TOOLCHAIN = re.compile(r"^toolchain\s+go(?P<version>\d+\.\d+(?:\.\d+)?)", re.MULTILINE)


def parse_gosum(text: str, *, file: str = "") -> List[Dependency]:
    seen = set()
    out: List[Dependency] = []
    for match in _GOSUM_LINE.finditer(text):
        key = (match.group("name"), match.group("version"))
        if key in seen:
            continue
        seen.add(key)
        out.append(_dep(match.group("name"), match.group("version"), "golang", file, "gosum"))
    return out


def parse_gomod(text: str, *, file: str = "") -> List[Dependency]:
    out: List[Dependency] = []
    toolchain = _GOMOD_TOOLCHAIN.search(text)
    if toolchain:
        out.append(_dep("go", toolchain.group("version"), "golang", file, "go.mod toolchain"))
    directive = _GOMOD_GO.search(text)
    if directive:
        out.append(
            _dep("go", directive.group("version"), "golang", file, "go.mod go directive", RANGE)
        )
    return out


_MIX_ENTRY = re.compile(
    r'"(?P<name>[A-Za-z0-9_]+)":\s*\{:hex,\s*:[A-Za-z0-9_]+,\s*"(?P<version>[^"]+)"'
)


def parse_mix_lock(text: str, *, file: str = "") -> List[Dependency]:
    return [
        _dep(match.group("name"), match.group("version"), "hex", file, "mix-lock")
        for match in _MIX_ENTRY.finditer(text)
    ]


def parse_package_json(text: str, *, file: str = "") -> List[Dependency]:
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return []
    except (json.JSONDecodeError, RecursionError):
        return []
    out: List[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        mapping = payload.get(section) or {}
        if not isinstance(mapping, dict):
            continue
        for name, spec in mapping.items():
            if not isinstance(spec, str):
                continue
            exact = bool(re.fullmatch(r"\d+\.\d+\.\d+", spec))
            out.append(
                _dep(
                    name,
                    spec.lstrip("^~>=< "),
                    "npm",
                    file,
                    "package.json",
                    PINNED if exact else RANGE,
                )
            )
    engines = payload.get("engines")
    if isinstance(engines, dict) and isinstance(engines.get("node"), str):
        out.append(
            _dep(
                "node", engines["node"].lstrip("^~>=< "), "npm", file, "package.json engines", RANGE
            )
        )
    return out


_TOOL_VERSIONS = re.compile(r"^(?P<tool>[a-zA-Z0-9_-]+)\s+(?P<version>[0-9][^\s#]*)", re.MULTILINE)


def parse_tool_versions(text: str, *, file: str = "") -> List[Dependency]:
    out = []
    if file.endswith(".toml"):
        in_tools = False
        for line in text.splitlines():
            if line.strip().startswith("["):
                in_tools = line.strip() == "[tools]"
            if in_tools:
                match = re.fullmatch(
                    r'\s*([a-zA-Z0-9_-]+)\s*=\s*["\']([0-9.]+)["\']\s*(?:#.*)?', line
                )
                if match:
                    out.extend(parse_plain_version(match[2], file=file, name=match[1]))
    else:
        for match in _TOOL_VERSIONS.finditer(text):
            out.extend(
                parse_plain_version(match.group("version"), file=file, name=match.group("tool"))
            )
    return out


def parse_plain_version(text: str, *, file: str = "", name: str = "") -> List[Dependency]:
    """`.nvmrc`, `.python-version` and friends: one version per file."""
    for line in text.splitlines():
        line = line.strip().lstrip("v")
        if line and line[0].isdigit():
            kind = PINNED if re.match(r"^\d+\.\d+\.\d+", line) else RANGE
            name = {"nodejs": "node"}.get(name, name)
            ecosystem = {"node": "npm", "go": "golang", "python": "pypi"}.get(name, "generic")
            return [_dep(name, line, ecosystem, file, "version-file", kind)]
    return []


PARSERS = {
    "npm-lock": parse_npm_lock,
    "yarn-lock": parse_yarn_lock,
    "pnpm-lock": parse_pnpm_lock,
    "requirements": parse_requirements,
    "toml-lock": parse_toml_lock,
    "composer-lock": parse_composer_lock,
    "pipfile-lock": parse_pipfile_lock,
    "gemfile-lock": parse_gemfile_lock,
    "gosum": parse_gosum,
    "mix-lock": parse_mix_lock,
}


def parse(parser: str, text: str, *, file: str = "") -> List[Dependency]:
    function = PARSERS.get(parser)
    if function is None:
        return []
    if parser == "toml-lock":
        return parse_toml_lock(text, file=file)
    try:
        return function(text, file=file)
    except (ValueError, TypeError, AttributeError, RecursionError):
        return []


def find(
    dependencies: List[Dependency], name: str, ecosystem: Optional[str] = None
) -> List[Dependency]:
    target = name.strip().lower()
    return [
        dependency
        for dependency in dependencies
        if dependency.normalized == target
        and (ecosystem is None or dependency.ecosystem == ecosystem)
    ]
