"""Endpoint audit: what would *this machine's* clients accept?"""

from __future__ import annotations

import datetime
from typing import List

from .. import __version__
from ..model import (
    ACTION_REVIEW,
    STATUS_UNABLE,
    TAG_CREDENTIALS,
    TAG_SPKI_TRUSTED,
    TAG_VERIFICATION_DISABLED,
    Evidence,
    Finding,
    Report,
)
from . import env_checks, network, platforminfo, runtimes, stores
from .context import EndpointContext

__all__ = ["EndpointContext", "audit", "credential_guidance_finding"]


def credential_guidance_finding(ctx: EndpointContext, findings: List[Finding]) -> List[Finding]:
    """Conditional credential guidance - never an automatic 'rotate everything'."""
    exposure = [
        finding
        for finding in findings
        if finding.status in ("known_indicator", "suspicious")
        and (
            TAG_SPKI_TRUSTED in finding.tags
            or TAG_VERIFICATION_DISABLED in finding.tags
            or "compromised-spki-present" in finding.tags
        )
    ]
    guidance = ctx.data.incident.get("credential_guidance", {})
    references = [
        source["url"] if isinstance(source, dict) else source
        for source in guidance.get("sources", [])
    ]
    if not exposure:
        return []
    conditions = guidance.get("conditions", [])
    steps: List[str] = []
    for condition in conditions:
        steps.append("%s [%s]" % (condition.get("when", ""), condition.get("state", "")))
        steps.extend("    - %s" % item for item in condition.get("do", []))
    return [
        Finding(
            id="ENDPOINT-CREDENTIAL-REVIEW",
            title="Credential exposure window needs review (scope depends on evidence)",
            status=STATUS_UNABLE,
            severity="medium",
            confidence="medium",
            action=ACTION_REVIEW,
            summary=(
                guidance.get("principle", "")
                + " This audit changes no credential and cannot determine whether anything was intercepted."
            ),
            evidence=[
                Evidence(what="triggered by", value="%s (%s)" % (finding.id, finding.title))
                for finding in exposure
            ],
            remediation=steps,
            references=references,
            tags=[TAG_CREDENTIALS],
            data_version=str(ctx.data.incident.get("data_version", "")),
        )
    ]


def audit(ctx: EndpointContext) -> Report:
    """Run every endpoint check and return the assembled report."""
    report = Report(
        tool="endpoint audit",
        tool_version=__version__,
        scope="endpoint (%s)" % ctx.system,
        started_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    report.context = dict(platforminfo.describe(ctx), **ctx.describe())
    report.data_sources = ctx.data.describe_sources()

    if ctx.data.checksum_status != "verified":
        report.errors.append(
            "data integrity: %s (%s)"
            % (ctx.data.checksum_status, "; ".join(ctx.data.checksum_problems) or "no detail")
        )
    for problem in ctx.data.schema_problems:
        report.errors.append("data schema: %s" % problem)

    if not ctx.runner.enabled:
        report.add(
            Finding(
                id="ENDPOINT-COMMANDS-SKIPPED",
                title="Executable probes were not run",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary="OS keychain enumeration and installed runtime/package probes need --commands. "
                "Only enable probes when the installed executables and startup hooks are trusted.",
            )
        )

    sources: List[stores.TrustSource] = []
    sources.extend(stores.collect_os_sources(ctx))
    sources.extend(stores.extra_bundle_sources(ctx))

    override_findings, override_sources = env_checks.collect_override_sources(ctx)
    sources.extend(override_sources)

    runtime_findings, runtime_sources = runtimes.audit(ctx)
    sources.extend(runtime_sources)

    report.extend(platforminfo.environment_findings(ctx))
    report.extend(stores.evaluate_sources(ctx, sources))
    report.extend(stores.linux_ca_conf_findings(ctx))
    report.extend(stores.windows_root_update_findings(ctx))
    report.extend(platforminfo.ca_package_findings(ctx))
    report.extend(runtime_findings)
    report.extend(override_findings)
    report.extend(env_checks.verification_findings(ctx))

    if ctx.network_host:
        report.notes.append(
            "An online test was performed against %s because --network-test was given. That host "
            "learned this machine's source address, TLS fingerprint and client identity."
            % ctx.network_host
        )
        report.extend(network.audit(ctx, ctx.network_host))
    else:
        report.notes.append(
            "Offline run: no network connection was made. Pass --network-test HOST to add an online "
            "check, which discloses this machine's address to that host."
        )

    report.extend(credential_guidance_finding(ctx, report.findings))

    report.notes.append(
        "Trust store contents and component versions are corroborating evidence. The decisive question "
        "is whether a particular client accepts a chain through one of the compromised keys, which can "
        "differ per client on the same machine."
    )
    report.notes.append(
        "Nothing was modified: no certificate was added or removed, no package was installed, no "
        "registry key or keychain entry was written."
    )
    report.notes.extend(ctx.notes)
    report.errors.extend(ctx.errors)
    return report
