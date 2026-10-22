"""Platform identification, container detection and CA package version checks."""

from __future__ import annotations

import platform
import re
from typing import Any, Dict, List, Optional, Tuple

from .. import versions
from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_UNABLE,
    TAG_OUTDATED_COMPONENT,
    Evidence,
    Finding,
)
from ..util import first_line
from .context import EndpointContext


def read_os_release(ctx: EndpointContext) -> Dict[str, str]:
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = ctx.path(candidate).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        values: Dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line or line.strip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
        if values:
            return values
    return {}


def os_identifiers(ctx: EndpointContext) -> List[str]:
    """Distribution ids, most specific first (``ID`` then ``ID_LIKE``)."""
    if ctx.is_darwin:
        return ["darwin"]
    if ctx.is_windows:
        return ["windows"]
    release = read_os_release(ctx)
    identifiers: List[str] = []
    if release.get("ID"):
        identifiers.append(release["ID"].lower())
    for like in release.get("ID_LIKE", "").split():
        if like.lower() not in identifiers:
            identifiers.append(like.lower())
    return identifiers


def detect_container(ctx: EndpointContext) -> Optional[str]:
    if ctx.path("/.dockerenv").exists():
        return "docker (/.dockerenv present)"
    if ctx.path("/run/.containerenv").exists():
        return "podman (/run/.containerenv present)"
    try:
        cgroup = ctx.path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        cgroup = ""
    if re.search(r"docker|containerd|kubepods|lxc", cgroup):
        return "container runtime referenced in /proc/1/cgroup"
    return None


def detect_wsl(ctx: EndpointContext) -> Optional[str]:
    if not ctx.is_linux:
        return None
    if ctx.env.get("WSL_DISTRO_NAME"):
        return "WSL distribution %s" % ctx.env["WSL_DISTRO_NAME"]
    try:
        proc_version = ctx.path("/proc/version").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if "microsoft" in proc_version.lower():
        return "WSL kernel reported in /proc/version"
    return None


def describe(ctx: EndpointContext) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "system": ctx.system,
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    if ctx.is_darwin:
        result = ctx.runner.run(["sw_vers", "-productVersion"])
        if result.ok:
            info["os_version"] = first_line(result.stdout)
        build = ctx.runner.run(["sw_vers", "-buildVersion"])
        if build.ok:
            info["os_build"] = first_line(build.stdout)
    elif ctx.is_windows:
        info["os_version"] = platform.version()
        info["os_release"] = platform.release()
    else:
        release = read_os_release(ctx)
        if release:
            info["os_id"] = release.get("ID", "")
            info["os_version"] = release.get("VERSION_ID", "")
            info["os_name"] = release.get("PRETTY_NAME", "")
    return info


def environment_findings(ctx: EndpointContext) -> List[Finding]:
    """Container and WSL context, which change what a verdict can mean."""
    findings: List[Finding] = []
    container = detect_container(ctx)
    if container:
        findings.append(
            Finding(
                id="ENDPOINT-CONTAINER-CONTEXT",
                title="Audit is running inside a container",
                status=STATUS_UNABLE,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "The result describes this container image only. A patched host says nothing about "
                    "an image that has not been rebuilt, and vice versa."
                ),
                evidence=[Evidence(what="indicator", value=container)],
                remediation=[
                    "Rebuild the image after the base image ships the fixed ca-certificates package, then redeploy.",
                    "Audit the host separately.",
                ],
            )
        )
    wsl = detect_wsl(ctx)
    if wsl:
        findings.append(
            Finding(
                id="ENDPOINT-WSL-CONTEXT",
                title="Audit is running inside WSL",
                status=STATUS_UNABLE,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "WSL has its own Linux trust store. Patching Windows does not patch it, and this "
                    "run says nothing about the Windows host."
                ),
                evidence=[Evidence(what="indicator", value=wsl)],
                remediation=["Audit the Windows host separately from a Windows shell."],
            )
        )
    return findings


_PACKAGE_QUERIES = {
    "dpkg": lambda package: ["dpkg-query", "-W", "-f=${Version}", package],
    "rpm": lambda package: ["rpm", "-q", "--qf", "%{VERSION}", package],
    "pacman": lambda package: ["pacman", "-Q", package],
    "apk": lambda package: ["apk", "info", "-v", package],
    "brew": lambda package: ["brew", "list", "--versions", package],
}


def query_package_version(ctx: EndpointContext, manager: str, package: str) -> Tuple[str, str]:
    """Return ``(version, problem)``; exactly one of the two is non-empty."""
    builder = _PACKAGE_QUERIES.get(manager)
    if builder is None:
        return "", "package manager %s is not supported by this audit" % manager
    result = ctx.runner.run(builder(package))
    if not result.ok:
        return "", result.error or "%s query failed (exit %d)" % (manager, result.returncode)
    text = first_line(result.stdout)
    if not text:
        return "", "%s reported no version for %s" % (manager, package)
    if manager == "dpkg":
        return text.strip(), ""
    if manager == "rpm":
        return text.strip(), ""
    if manager in ("pacman", "brew"):
        parts = text.split()
        return (parts[1], "") if len(parts) > 1 else ("", "unexpected %s output" % manager)
    if manager == "apk":
        match = re.match(re.escape(package) + r"-(\d.*)$", text.strip())
        return (match.group(1), "") if match else ("", "unexpected apk output")
    return "", "unhandled manager %s" % manager


def ca_package_findings(ctx: EndpointContext) -> List[Finding]:
    """Compare the installed OS CA bundle package against the fixed-version policy."""
    policy_entries = ctx.data.policy.get("os_ca_bundles", [])
    identifiers = os_identifiers(ctx)
    release = read_os_release(ctx)
    os_version = release.get("VERSION_ID", "")
    data_version = str(ctx.data.policy.get("data_version", ""))
    policy_sources = [
        source["url"] if isinstance(source, dict) else source
        for source in ctx.data.policy.get("sources", [])
    ]

    candidates = []
    for identifier in identifiers:
        for entry in policy_entries:
            if identifier not in [value.lower() for value in entry.get("os_ids", [])]:
                continue
            prefix = str(entry.get("os_version_prefix", ""))
            if prefix and not (os_version == prefix or os_version.startswith(prefix + ".")):
                continue
            candidates.append(entry)
        if candidates:
            break

    if not candidates:
        return [
            Finding(
                id="ENDPOINT-CA-PACKAGE-NO-POLICY",
                title="No fixed-version policy entry matches this platform",
                status=STATUS_UNABLE,
                severity="medium" if ctx.is_linux else "info",
                confidence="high",
                action=ACTION_REVIEW if ctx.is_linux else ACTION_NONE,
                summary=(
                    "data/policies/fixed-versions.json has no row for %s %s, so the installed CA bundle "
                    "version cannot be judged here."
                    % (identifiers[0] if identifiers else ctx.system, os_version or "")
                ),
                evidence=[
                    Evidence(what="detected platform", value=" ".join(identifiers) or ctx.system)
                ],
                remediation=[
                    "Check your distributor's advisory for the fixed ca-certificates version and compare by hand.",
                    "Contributions adding a distribution row to data/policies/fixed-versions.json are welcome.",
                ],
                references=policy_sources,
                data_version=data_version,
            )
        ]

    findings: List[Finding] = []
    for entry in candidates:
        manager = str(entry.get("package_manager", ""))
        package = str(entry.get("package", ""))
        fixed = entry.get("fixed_version")
        scheme = str(entry.get("scheme", "generic"))
        installed, problem = query_package_version(ctx, manager, package)
        references = list(entry.get("sources", [])) or policy_sources
        if problem:
            findings.append(
                Finding(
                    id="ENDPOINT-CA-PACKAGE-UNKNOWN",
                    title="Installed CA bundle package version could not be determined",
                    status=STATUS_UNABLE,
                    severity="medium" if ctx.is_linux else "info",
                    confidence="high",
                    action=ACTION_REVIEW if ctx.is_linux else ACTION_NONE,
                    summary="Could not read the version of %s via %s." % (package, manager),
                    evidence=[Evidence(what="reason", value=problem)],
                    remediation=[
                        "Run the package manager query by hand and compare with the fixed version in data/policies/fixed-versions.json.",
                    ],
                    references=references,
                    data_version=data_version,
                )
            )
            continue
        verdict = versions.evaluate(installed, fixed, scheme)
        evidence = [
            Evidence(what="package", value="%s (%s)" % (package, manager)),
            Evidence(what="installed version", value=installed),
            Evidence(what="fixed version in policy", value=str(fixed) if fixed else "not recorded"),
        ]
        if entry.get("note"):
            evidence.append(Evidence(what="policy note", value=str(entry["note"])))
        if verdict == versions.OUTDATED:
            findings.append(
                Finding(
                    id="ENDPOINT-CA-PACKAGE-OUTDATED",
                    title="OS CA bundle package predates the fix",
                    status=STATUS_KNOWN_INDICATOR,
                    severity="medium",
                    confidence="medium",
                    action=ACTION_REQUIRED,
                    summary=(
                        "%s %s is below the recorded fixed version %s. On this distribution the removal of "
                        "trust for the compromised intermediates is delivered by that package, so an older "
                        "version is evidence of work to do - not proof that a forged chain is accepted."
                        % (package, installed, fixed)
                    ),
                    evidence=evidence,
                    remediation=[
                        "Update the package from the distribution's official channel, for example `apt update && apt install --only-upgrade ca-certificates` or the dnf/pacman/apk equivalent.",
                        "Restart long-running processes afterwards: a running daemon keeps the bundle it loaded at start.",
                        "Rebuild container images that derive from this platform.",
                    ],
                    references=references,
                    tags=[TAG_OUTDATED_COMPONENT],
                    data_version=data_version,
                )
            )
        elif verdict == versions.OK:
            findings.append(
                Finding(
                    id="ENDPOINT-CA-PACKAGE-CURRENT",
                    title="OS CA bundle package is at or above the recorded fixed version",
                    status=STATUS_NOT_FOUND,
                    severity="pass",
                    confidence="medium",
                    action=ACTION_NONE,
                    summary=(
                        "Version evidence only. A matching version does not prove the running processes "
                        "reloaded the bundle, and the fixed-version table itself is transcribed data that "
                        "can lag behind the distribution."
                    ),
                    evidence=evidence,
                    references=references,
                    data_version=data_version,
                )
            )
        else:
            findings.append(
                Finding(
                    id="ENDPOINT-CA-PACKAGE-UNCOMPARABLE",
                    title="Installed CA bundle version could not be compared with the policy",
                    status=STATUS_UNABLE,
                    severity="medium" if ctx.is_linux else "info",
                    confidence="high",
                    action=ACTION_REVIEW if ctx.is_linux else ACTION_NONE,
                    summary="Either the installed version or the policy entry is not comparable.",
                    evidence=evidence,
                    remediation=[
                        "Compare the two version strings by hand against your distributor's advisory."
                    ],
                    references=references,
                    data_version=data_version,
                )
            )
    return findings
