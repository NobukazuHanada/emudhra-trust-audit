"""Runtimes, developer CLIs and the trust stores they carry of their own.

An operating system update does not touch a Node.js build-in root list, a JDK
``cacerts`` file or a ``certifi`` wheel. Each is queried through its own
read-only command and, where the store can be read, its contents are matched
against the indicator data like any other trust source.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

from .. import jks, versions
from ..certs import CertificateParseError, parse_bundle, parse_certificate
from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_UNABLE,
    TAG_OUTDATED_COMPONENT,
    TAG_VERIFICATION_DISABLED,
    Evidence,
    Finding,
)
from ..util import first_line, read_regular_file
from .context import EndpointContext
from .stores import ROLE_INDEPENDENT, ROLE_OVERRIDE, TrustSource

CERTIFI_PROBE = (
    "import json,sys\n"
    "out={'python': sys.version.split()[0]}\n"
    "try:\n"
    "    import certifi\n"
    "    out['certifi']=certifi.__version__\n"
    "    out['where']=certifi.where()\n"
    "except Exception as exc:\n"
    "    out['error']=type(exc).__name__\n"
    "print(json.dumps(out))\n"
)

NODE_ROOTS_PROBE = "process.stdout.write(require('tls').rootCertificates.join('\\n'))"


def _policy_entry(ctx: EndpointContext, policy_id: str) -> Optional[dict]:
    for entry in ctx.data.policy.get("packages", []):
        if entry.get("id") == policy_id:
            return entry
    return None


def _version_finding(
    ctx: EndpointContext,
    *,
    component: str,
    installed: str,
    policy_id: str,
    detail: str = "",
    location: str = "",
) -> Finding:
    """Compare an installed version against the policy, honouring branch scope."""
    entry = _policy_entry(ctx, policy_id)
    data_version = str(ctx.data.policy.get("data_version", ""))
    references = list(entry.get("sources", [])) if entry else []
    evidence = [Evidence(what="installed version", value=installed, source=location)]
    if detail:
        evidence.append(Evidence(what="detail", value=detail))

    if entry is None:
        return Finding(
            id="ENDPOINT-COMPONENT-NO-POLICY",
            title="%s version recorded, no fixed version in policy data" % component,
            status=STATUS_UNABLE,
            severity="info",
            confidence="high",
            action=ACTION_NONE,
            summary="No fixed version is recorded for %s, so this is context, not a verdict."
            % component,
            evidence=evidence,
            data_version=data_version,
        )

    branch = versions.branch_of(installed, entry.get("branches", []))
    if branch is None:
        return Finding(
            id="ENDPOINT-COMPONENT-BRANCH-UNKNOWN",
            title="%s is on a release branch the policy does not cover" % component,
            status=STATUS_UNABLE,
            severity="medium",
            confidence="high",
            action=ACTION_REVIEW,
            summary=(
                "%s %s does not fall in any branch recorded in the policy (%s). A branch with no recorded "
                "fix is not the same as a branch with no problem."
                % (
                    component,
                    installed,
                    ", ".join(str(b.get("match")) for b in entry.get("branches", [])),
                )
            ),
            evidence=evidence,
            remediation=[
                "Check the upstream release notes for %s and update to a release that carries the fix."
                % component,
                "Consider moving to a supported release branch if this one is end of life.",
            ],
            references=references,
            data_version=data_version,
        )

    fixed = branch.get("fixed")
    evidence.append(
        Evidence(what="fixed version in policy", value=str(fixed) if fixed else "not recorded")
    )
    verdict = versions.evaluate(installed, fixed, str(entry.get("scheme", "generic")))
    if verdict == versions.OUTDATED:
        return Finding(
            id="ENDPOINT-COMPONENT-OUTDATED",
            title="%s predates the fixed release" % component,
            status=STATUS_KNOWN_INDICATOR,
            severity="medium",
            confidence="medium",
            action=ACTION_REQUIRED,
            summary=(
                "%s %s is below the recorded fixed version %s. Version evidence only: it does not by "
                "itself prove this component would accept a forged chain."
                % (component, installed, fixed)
            ),
            evidence=evidence,
            remediation=[
                "Update %s from its official channel and restart anything using it." % component,
                "Re-run this audit afterwards to confirm the new version is picked up.",
            ],
            references=references,
            tags=[TAG_OUTDATED_COMPONENT],
            data_version=data_version,
        )
    if verdict == versions.OK:
        return Finding(
            id="ENDPOINT-COMPONENT-CURRENT",
            title="%s is at or above the recorded fixed release" % component,
            status=STATUS_NOT_FOUND,
            severity="pass",
            confidence="medium",
            action=ACTION_NONE,
            summary="Version evidence only; running processes may still hold an older copy in memory.",
            evidence=evidence,
            references=references,
            data_version=data_version,
        )
    return Finding(
        id="ENDPOINT-COMPONENT-UNCOMPARABLE",
        title="%s version could not be compared with the policy" % component,
        status=STATUS_UNABLE,
        severity="info",
        confidence="high",
        action=ACTION_NONE,
        summary="Neither a pass nor a failure: the comparison itself was not possible.",
        evidence=evidence,
        references=references,
        data_version=data_version,
    )


def _simple_version(ctx: EndpointContext, argv: List[str]) -> str:
    result = ctx.runner.run(argv)
    if not result.ok:
        return ""
    return versions.extract_version(first_line(result.stdout) or first_line(result.stderr))


def check_node(ctx: EndpointContext) -> Tuple[List[Finding], List[TrustSource]]:
    findings: List[Finding] = []
    sources: List[TrustSource] = []
    version = _simple_version(ctx, ["node", "--version"])
    if not version:
        return findings, sources
    findings.append(
        _version_finding(
            ctx,
            component="Node.js",
            installed=version,
            policy_id="nodejs",
            location="node --version",
        )
    )
    probe = ctx.runner.run(["node", "-p", NODE_ROOTS_PROBE], timeout=60)
    if probe.ok and "BEGIN CERTIFICATE" in probe.stdout:
        sources.append(
            TrustSource(
                label="Node.js built-in root certificates",
                location="node require('tls').rootCertificates",
                role=ROLE_INDEPENDENT,
                certificates=parse_bundle(
                    probe.stdout.encode("utf-8", "replace"), source="node rootCertificates"
                ),
            )
        )
    elif probe.error or probe.returncode != 0:
        sources.append(
            TrustSource(
                label="Node.js built-in root certificates",
                location="node require('tls').rootCertificates",
                role=ROLE_INDEPENDENT,
                readable=False,
                detail=probe.error or "node exited %d" % probe.returncode,
            )
        )
    return findings, sources


def check_python(ctx: EndpointContext) -> Tuple[List[Finding], List[TrustSource]]:
    findings: List[Finding] = []
    sources: List[TrustSource] = []
    seen: Dict[str, str] = {}
    for interpreter in ("python3", "python"):
        path = ctx.runner.which(interpreter)
        if not path or path in seen.values():
            continue
        result = ctx.runner.run([interpreter, "-c", CERTIFI_PROBE])
        if not result.ok:
            continue
        try:
            payload = json.loads(first_line(result.stdout) or "{}")
        except json.JSONDecodeError:
            continue
        seen[interpreter] = path
        if payload.get("certifi"):
            findings.append(
                _version_finding(
                    ctx,
                    component="%s certifi" % interpreter,
                    installed=str(payload["certifi"]),
                    policy_id="python-certifi",
                    detail="Python %s" % payload.get("python", "?"),
                    location=ctx.show(path),
                )
            )
            where = payload.get("where")
            if where:
                bundle_path = ctx.path(where)
                try:
                    blob = read_regular_file(bundle_path)
                except OSError as error:
                    sources.append(
                        TrustSource(
                            label="%s certifi bundle" % interpreter,
                            location=ctx.show(where),
                            role=ROLE_INDEPENDENT,
                            readable=False,
                            detail=str(error.strerror or error),
                        )
                    )
                else:
                    sources.append(
                        TrustSource(
                            label="%s certifi bundle" % interpreter,
                            location=ctx.show(where),
                            role=ROLE_INDEPENDENT,
                            certificates=parse_bundle(blob, source=ctx.show(where)),
                        )
                    )
    return findings, sources


def check_java(ctx: EndpointContext) -> Tuple[List[Finding], List[TrustSource]]:
    findings: List[Finding] = []
    sources: List[TrustSource] = []
    result = ctx.runner.run(["java", "-XshowSettings:properties", "-version"])
    if not result.ok:
        return findings, sources
    text = result.stderr + result.stdout
    match = re.search(r"java\.home\s*=\s*(.+)", text)
    if not match:
        return findings, sources
    java_home = match.group(1).strip()
    version_match = re.search(r'version "([^"]+)"', text)
    version = versions.extract_version(version_match.group(1)) if version_match else ""
    findings.append(
        Finding(
            id="ENDPOINT-JAVA-PRESENT",
            title="A JDK/JRE with its own truststore was found",
            status=STATUS_UNABLE,
            severity="info",
            confidence="high",
            action=ACTION_NONE,
            summary="Java trusts the CAs in its own cacerts file; OS updates do not change it.",
            evidence=[
                Evidence(what="java.home", value=ctx.show(java_home)),
                Evidence(what="version", value=version or "unknown"),
            ],
            remediation=[
                "Update the JDK from its vendor, or have the vendor's fixed cacerts applied, then restart Java services.",
            ],
        )
    )
    for relative in ("lib/security/cacerts", "jre/lib/security/cacerts"):
        candidate = ctx.path(java_home + "/" + relative)
        if not candidate.is_file():
            continue
        entries = jks.read_file(candidate)
        if entries is None:
            try:
                kind = jks.detect_format(read_regular_file(candidate)[:8])
            except OSError:
                kind = "unreadable"
            sources.append(
                TrustSource(
                    label="Java cacerts",
                    location=ctx.show(candidate),
                    role=ROLE_INDEPENDENT,
                    readable=False,
                    detail="keystore format %s cannot be read without keytool" % kind,
                )
            )
            continue
        certificates = []
        for alias, der in entries:
            try:
                certificates.append(parse_certificate(der, source="cacerts:%s" % alias))
            except CertificateParseError:
                continue
        sources.append(
            TrustSource(
                label="Java cacerts",
                location=ctx.show(candidate),
                role=ROLE_INDEPENDENT,
                certificates=certificates,
            )
        )
        break
    return findings, sources


def check_git(ctx: EndpointContext) -> Tuple[List[Finding], List[TrustSource]]:
    findings: List[Finding] = []
    sources: List[TrustSource] = []
    if ctx.runner.which("git") is None:
        return findings, sources
    verify = ctx.runner.run(["git", "config", "--get", "http.sslVerify"])
    value = first_line(verify.stdout).strip().lower()
    if verify.ok and value in ("false", "0", "no", "off"):
        findings.append(
            Finding(
                id="ENDPOINT-GIT-VERIFY-DISABLED",
                title="git is configured not to verify TLS certificates",
                status=STATUS_KNOWN_INDICATOR,
                severity="critical",
                confidence="high",
                action=ACTION_REQUIRED,
                summary=(
                    "http.sslVerify is false in this user's effective git configuration, so every clone, "
                    "fetch and push accepts any certificate. Fix this before anything else on this list."
                ),
                evidence=[Evidence(what="git config http.sslVerify", value=value)],
                remediation=[
                    "Find the scope that sets it with `git config --show-origin --get http.sslVerify` and remove the entry.",
                    "If a TLS-inspecting proxy was the reason, set http.sslCAInfo to the proxy CA instead of disabling verification.",
                ],
                tags=[TAG_VERIFICATION_DISABLED],
            )
        )
    cainfo = ctx.runner.run(["git", "config", "--get", "http.sslCAInfo"])
    if cainfo.ok and first_line(cainfo.stdout).strip():
        bundle = first_line(cainfo.stdout).strip()
        path = ctx.path(bundle)
        if path.is_file():
            try:
                blob = read_regular_file(path)
            except OSError as error:
                sources.append(
                    TrustSource(
                        label="git http.sslCAInfo bundle",
                        location=ctx.show(bundle),
                        role=ROLE_OVERRIDE,
                        readable=False,
                        detail=str(error.strerror or error),
                    )
                )
            else:
                sources.append(
                    TrustSource(
                        label="git http.sslCAInfo bundle",
                        location=ctx.show(bundle),
                        role=ROLE_OVERRIDE,
                        certificates=parse_bundle(blob, source=ctx.show(bundle)),
                    )
                )
        findings.append(
            Finding(
                id="ENDPOINT-GIT-CUSTOM-CA",
                title="git uses a custom CA bundle",
                status=STATUS_KNOWN_INDICATOR,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary=(
                    "git reads trust anchors from this file instead of the OS store, so updating the OS "
                    "does not necessarily change what git accepts."
                ),
                evidence=[Evidence(what="http.sslCAInfo", value=ctx.show(bundle))],
                remediation=[
                    "Rebuild that bundle from an updated upstream source, or point git back at the OS store.",
                ],
            )
        )
    return findings, sources


def check_clients(ctx: EndpointContext) -> List[Finding]:
    """Record versions of the clients that do TLS on a developer machine."""
    findings: List[Finding] = []
    probes = (
        ("Go toolchain", ["go", "version"], "go"),
        ("pip", ["pip3", "--version"], "pip"),
        ("uv", ["uv", "--version"], "uv"),
        ("Claude Code CLI", ["claude", "--version"], "claude-code"),
    )
    for component, argv, policy_id in probes:
        if ctx.runner.which(argv[0]) is None:
            continue
        version = _simple_version(ctx, argv)
        if version:
            findings.append(
                _version_finding(
                    ctx,
                    component=component,
                    installed=version,
                    policy_id=policy_id,
                    location=" ".join(argv),
                )
            )

    for component, argv in (
        ("curl", ["curl", "-V"]),
        ("OpenSSL", ["openssl", "version"]),
        ("Codex CLI", ["codex", "--version"]),
    ):
        if ctx.runner.which(argv[0]) is None:
            continue
        result = ctx.runner.run(argv)
        if not result.ok:
            continue
        line = first_line(result.stdout) or first_line(result.stderr)
        findings.append(
            Finding(
                id="ENDPOINT-CLIENT-VERSION",
                title="%s version recorded" % component,
                status=STATUS_UNABLE,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "Recorded as context. Which trust store this client reads depends on how it was built, "
                    "so the version alone decides nothing."
                ),
                evidence=[
                    Evidence(
                        what="output",
                        value=versions.extract_version(line) or "unavailable",
                        source=" ".join(argv),
                    )
                ],
            )
        )
    return findings


def audit(ctx: EndpointContext) -> Tuple[List[Finding], List[TrustSource]]:
    findings: List[Finding] = []
    sources: List[TrustSource] = []
    for checker in (check_node, check_python, check_java, check_git):
        check_findings, check_sources = checker(ctx)
        findings.extend(check_findings)
        sources.extend(check_sources)
    findings.extend(check_clients(ctx))
    return findings, sources
