"""Inventory and dependency-version checks for a project directory."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .. import versions
from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_UNABLE,
    TAG_INDEPENDENT_STORE,
    TAG_OUTDATED_COMPONENT,
    Evidence,
    Finding,
)
from . import parsers
from .parsers import Dependency
from .scan import ProjectContext

MAX_LISTED_FILES = 25


def _entry_files(ctx: ProjectContext, entries: List[dict]) -> Dict[str, List[str]]:
    """Map a catalogue entry id to the relative paths that match its globs."""
    found: Dict[str, List[str]] = {}
    for entry in entries:
        matches = ctx.match(entry.get("files", []))
        if matches:
            found[str(entry["id"])] = [item.relative for item in matches]
    return found


def inventory_findings(
    ctx: ProjectContext, dependencies: Optional[List[Dependency]] = None
) -> List[Finding]:
    inventory = ctx.data.inventory
    manifests = _entry_files(ctx, inventory.get("manifests", []))
    lockfiles = _entry_files(ctx, inventory.get("lockfiles", []))
    containers = [item.relative for item in ctx.match(inventory.get("container_files", []))]
    ci_files = [item.relative for item in ctx.match(inventory.get("ci_files", []))]
    tool_files = [item.relative for item in ctx.match(inventory.get("tool_version_files", []))]
    config_files = [item.relative for item in ctx.match(inventory.get("config_files", []))]

    findings: List[Finding] = []
    evidence: List[Evidence] = []
    for label, mapping in (("manifest", manifests), ("lock file", lockfiles)):
        for entry_id, paths in sorted(mapping.items()):
            evidence.append(
                Evidence(
                    what="%s (%s)" % (label, entry_id),
                    value=", ".join(paths[:MAX_LISTED_FILES])
                    + (" ..." if len(paths) > MAX_LISTED_FILES else ""),
                )
            )
    for label, paths in (
        ("container definition", containers),
        ("CI definition", ci_files),
        ("pinned tool version", tool_files),
        ("package manager config", config_files),
    ):
        if paths:
            evidence.append(
                Evidence(
                    what=label,
                    value=", ".join(paths[:MAX_LISTED_FILES])
                    + (" ..." if len(paths) > MAX_LISTED_FILES else ""),
                )
            )

    if not manifests and not lockfiles:
        findings.append(
            Finding(
                id="PROJECT-NO-MANIFEST",
                title="No dependency manifest or lock file was found",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary=(
                    "Nothing in this directory identifies a dependency set, so no statement can be made "
                    "about the versions it installs. Check that the audit was pointed at the project root."
                ),
                evidence=[Evidence(what="files walked", value=str(len(ctx.walk())))],
            )
        )
    else:
        findings.append(
            Finding(
                id="PROJECT-INVENTORY",
                title="Project inventory",
                status=STATUS_NOT_FOUND,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary="Files that determine which TLS and CA components this project uses.",
                evidence=evidence
                + (
                    [
                        Evidence(
                            what="excluded by .ca-trust-audit-ignore",
                            value=", ".join(ctx.ignored[:MAX_LISTED_FILES])
                            + (" ..." if len(ctx.ignored) > MAX_LISTED_FILES else ""),
                        )
                    ]
                    if ctx.ignored
                    else []
                ),
                data_version=str(inventory.get("data_version", "")),
            )
        )

    ecosystems_with_locks = {
        str(entry["ecosystem"])
        for entry in ctx.data.inventory.get("lockfiles", [])
        if str(entry["id"]) in lockfiles
    }
    manifest_ecosystems = {
        str(entry["ecosystem"])
        for entry in ctx.data.inventory.get("manifests", [])
        if str(entry["id"]) in manifests
    }
    # Only ecosystems that actually declare a dependency can have an undetermined
    # installed version; a manifest declaring nothing needs no lock file.
    declared = {item.ecosystem for item in (dependencies or [])}
    missing = sorted((manifest_ecosystems & declared) - ecosystems_with_locks)
    if missing:
        findings.append(
            Finding(
                id="PROJECT-NO-LOCKFILE",
                title="A manifest has no lock file, so installed versions are undetermined",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary=(
                    "Without a lock file the version actually installed is decided at install time, so "
                    "this audit cannot tell whether a fixed CA bundle or runtime is in use."
                ),
                evidence=[
                    Evidence(what="ecosystem without a lock file", value=name) for name in missing
                ],
                remediation=[
                    "Commit a lock file, or record the resolved versions some other way, so that CA-bundle "
                    "versions can be audited.",
                ],
            )
        )
    if ctx.truncated or ctx.problems:
        findings.append(
            Finding(
                id="PROJECT-SCAN-TRUNCATED",
                title="Project inspection is incomplete",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary="Some files were unavailable, unsupported, or exceeded scan limits. "
                + "; ".join(sorted(set(ctx.problems))),
                remediation=[
                    "Audit sub-directories separately, or raise max_files in data/rules/insecure-tls.json."
                ],
            )
        )
    return findings


def collect_dependencies(ctx: ProjectContext) -> List[Dependency]:
    """Parse every lock file and version-pinning file found in the project."""
    dependencies: List[Dependency] = []
    for entry in ctx.data.inventory.get("lockfiles", []):
        parser = str(entry.get("parser", ""))
        if parser in ("opaque", ""):
            if ctx.match(entry.get("files", [])):
                ctx.problems.append("unsupported lockfile format")
            continue
        for item in ctx.match(entry.get("files", [])):
            text = ctx.read_text(item.relative)
            if text is None:
                continue
            parsed = parsers.parse(parser, text, file=item.relative)
            if text.strip() and not parsed:
                ctx.problems.append("lockfile yielded no assessable dependencies")
            dependencies.extend(parsed)
    for item in ctx.match(["package.json"]):
        text = ctx.read_text(item.relative)
        if text is not None:
            dependencies.extend(parsers.parse_package_json(text, file=item.relative))
    for item in ctx.match(["go.mod"]):
        text = ctx.read_text(item.relative)
        if text is not None:
            dependencies.extend(parsers.parse_gomod(text, file=item.relative))
    for item in ctx.match([".tool-versions", "mise.toml", ".mise.toml"]):
        text = ctx.read_text(item.relative)
        if text is not None:
            dependencies.extend(parsers.parse_tool_versions(text, file=item.relative))
    for pattern, name in ((".nvmrc", "node"), (".node-version", "node"), (".go-version", "go")):
        for item in ctx.match([pattern]):
            text = ctx.read_text(item.relative)
            if text is not None:
                dependencies.extend(
                    parsers.parse_plain_version(text, file=item.relative, name=name)
                )
    for entry in ctx.data.inventory.get("manifests", []):
        if entry.get("id") not in ("npm", "pip-requirements", "gomod") and ctx.match(
            entry.get("files", [])
        ):
            ctx.problems.append("manifest inventoried without dependency parser")
    return dependencies


def _best_match(dependencies: List[Dependency], name: str) -> Optional[Dependency]:
    """Prefer a pinned version over a range when the same name appears twice."""
    candidates = parsers.find(dependencies, name)
    if not candidates:
        return None
    pinned = [item for item in candidates if item.kind == parsers.PINNED]
    return (pinned or candidates)[0]


def dependency_findings(ctx: ProjectContext, dependencies: List[Dependency]) -> List[Finding]:
    findings: List[Finding] = []
    policy = ctx.data.policy
    data_version = str(policy.get("data_version", ""))

    pairs = [
        (entry, dep)
        for entry in policy.get("packages", [])
        for dep in parsers.find(dependencies, str(entry.get("name", "")))
        if dep.ecosystem == entry.get("ecosystem")
    ]
    for entry, dependency in pairs:
        name = str(entry.get("name", ""))
        references = list(entry.get("sources", []))
        location = ctx.show(dependency.file) if dependency.file else ""
        evidence = [
            Evidence(
                what="package",
                value="%s (%s)" % (name, entry.get("ecosystem", "")),
                source=location,
            ),
            Evidence(
                what="version in project", value="%s (%s)" % (dependency.version, dependency.kind)
            ),
        ]
        if dependency.kind == parsers.RANGE:
            findings.append(
                Finding(
                    id="PROJECT-DEPENDENCY-RANGE",
                    title="%s is specified as a range, so the installed version is undetermined"
                    % name,
                    status=STATUS_UNABLE,
                    severity="medium",
                    confidence="high",
                    action=ACTION_REVIEW,
                    summary=(
                        "A range such as %s can resolve to a version from either side of the fix. Check the "
                        "lock file or the installed environment." % dependency.version
                    ),
                    evidence=evidence,
                    remediation=[
                        "Inspect the lock file, or run the ecosystem's own 'list installed' command."
                    ],
                    references=references,
                    locations=[dependency.file] if dependency.file else [],
                    data_version=data_version,
                )
            )
            continue
        branch = versions.branch_of(dependency.version, entry.get("branches", []))
        if branch is None:
            findings.append(
                Finding(
                    id="PROJECT-DEPENDENCY-BRANCH-UNKNOWN",
                    title="%s is on a release branch the policy does not cover" % name,
                    status=STATUS_UNABLE,
                    severity="medium",
                    confidence="high",
                    action=ACTION_REVIEW,
                    summary="No fixed version is recorded for this branch, which is not the same as no problem.",
                    evidence=evidence,
                    remediation=[
                        "Check the upstream release notes for a fixed release on this branch."
                    ],
                    references=references,
                    locations=[dependency.file] if dependency.file else [],
                    data_version=data_version,
                )
            )
            continue
        fixed = branch.get("fixed")
        evidence.append(
            Evidence(what="fixed version in policy", value=str(fixed) if fixed else "not recorded")
        )
        verdict = versions.evaluate(dependency.version, fixed, str(entry.get("scheme", "generic")))
        kind = str(entry.get("kind", ""))
        if verdict == versions.OUTDATED:
            findings.append(
                Finding(
                    id="PROJECT-DEPENDENCY-OUTDATED",
                    title="%s predates the fixed release" % name,
                    status=STATUS_KNOWN_INDICATOR,
                    severity="medium",
                    confidence="medium",
                    action=ACTION_REQUIRED,
                    summary=(
                        "%s %s is below the recorded fixed version %s.%s"
                        % (
                            name,
                            dependency.version,
                            fixed,
                            " This package carries its own CA bundle, so no operating system update will"
                            " fix it."
                            if kind == "ca-bundle-library"
                            else "",
                        )
                    ),
                    evidence=evidence,
                    remediation=[
                        "Update %s to %s or later and commit the refreshed lock file."
                        % (name, fixed),
                        "Rebuild any container image or virtual environment that pinned the old version.",
                    ],
                    references=references,
                    tags=[TAG_OUTDATED_COMPONENT]
                    + ([TAG_INDEPENDENT_STORE] if kind == "ca-bundle-library" else []),
                    locations=[dependency.file] if dependency.file else [],
                    data_version=data_version,
                )
            )
        elif verdict == versions.OK:
            findings.append(
                Finding(
                    id="PROJECT-DEPENDENCY-CURRENT",
                    title="%s is at or above the recorded fixed release" % name,
                    status=STATUS_NOT_FOUND,
                    severity="pass",
                    confidence="medium",
                    action=ACTION_NONE,
                    summary="Lock file evidence only; the installed environment may differ from the lock file.",
                    evidence=evidence,
                    references=references,
                    locations=[dependency.file] if dependency.file else [],
                    data_version=data_version,
                )
            )
        else:
            findings.append(
                Finding(
                    id="PROJECT-DEPENDENCY-UNCOMPARABLE",
                    title="%s version could not be compared with the policy" % name,
                    status=STATUS_UNABLE,
                    severity="info",
                    confidence="high",
                    action=ACTION_NONE,
                    summary="Neither a pass nor a failure.",
                    evidence=evidence,
                    references=references,
                    locations=[dependency.file] if dependency.file else [],
                    data_version=data_version,
                )
            )

    for entry in policy.get("watchlist", []):
        name = str(entry.get("name", ""))
        dependency = _best_match(dependencies, name)
        if dependency is None:
            continue
        is_bundle = str(entry.get("kind")) == "ca-bundle-library"
        findings.append(
            Finding(
                id="PROJECT-WATCHLIST-DEPENDENCY",
                title="%s is present and carries trust decisions of its own" % name,
                status=STATUS_UNABLE,
                severity="medium" if is_bundle else "info",
                confidence="high",
                action=ACTION_REVIEW if is_bundle else ACTION_NONE,
                summary=str(entry.get("reason", "")),
                evidence=[
                    Evidence(
                        what="version in project",
                        value="%s (%s)" % (dependency.version, dependency.kind),
                        source=ctx.show(dependency.file) if dependency.file else "",
                    )
                ],
                remediation=[
                    "Confirm with the upstream project which release carries the updated trust data, then update.",
                ]
                if is_bundle
                else [],
                locations=[dependency.file] if dependency.file else [],
                data_version=data_version,
            )
        )
    return findings


def dependency_summary(ctx: ProjectContext, dependencies: List[Dependency]) -> Tuple[int, int]:
    pinned = sum(1 for item in dependencies if item.kind == parsers.PINNED)
    return len(dependencies), pinned
