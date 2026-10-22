"""Environment variables that redirect or switch off certificate verification.

Only variable *names* and the bundle *paths* they point at are reported, and
paths are redacted. Values of proxy, token or password variables are never read
into the report - a proxy URL commonly embeds credentials.
"""

from __future__ import annotations

from typing import List, Tuple

from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    TAG_VERIFICATION_DISABLED,
    Evidence,
    Finding,
)
from .context import EndpointContext
from .stores import ROLE_OVERRIDE, TrustSource

#: Variables that point a client at a CA bundle other than the OS store.
CA_OVERRIDE_VARIABLES = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "AWS_CA_BUNDLE",
    "PIP_CERT",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
    "NIX_SSL_CERT_FILE",
)

#: Variables whose effect is to stop verifying certificates at all.
VERIFICATION_OFF_VARIABLES = (
    ("GIT_SSL_NO_VERIFY", ("1", "true", "yes", "on")),
    ("NODE_TLS_REJECT_UNAUTHORIZED", ("0",)),
    ("PYTHONHTTPSVERIFY", ("0",)),
)

#: Variables that exist but whose values must never be echoed.
OPAQUE_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "NO_PROXY",
)


def collect_override_sources(ctx: EndpointContext) -> Tuple[List[Finding], List[TrustSource]]:
    findings: List[Finding] = []
    sources: List[TrustSource] = []
    evidence: List[Evidence] = []
    for name in CA_OVERRIDE_VARIABLES:
        raw = ctx.env.get(name)
        if not raw:
            continue
        evidence.append(Evidence(what=name, value=ctx.show(raw)))
        target = ctx.path(raw)
        from .stores import _bundle_source, _directory_source

        if target.is_dir():
            source = _directory_source(ctx, raw, "%s directory" % name, ROLE_OVERRIDE)
        else:
            source = _bundle_source(ctx, raw, "%s bundle" % name, ROLE_OVERRIDE)
        sources.append(
            source
            or TrustSource(
                label="%s bundle" % name,
                location=ctx.show(raw),
                role=ROLE_OVERRIDE,
                readable=False,
                detail="the configured bundle is unavailable",
            )
        )
    if evidence:
        findings.append(
            Finding(
                id="ENDPOINT-CA-OVERRIDE-ENV",
                title="Environment variables redirect clients to a custom CA bundle",
                status=STATUS_KNOWN_INDICATOR,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary=(
                    "Clients that honour these variables ignore the operating system trust store, so an "
                    "OS update does not change what they accept. The bundles named here were scanned "
                    "separately; only the variable name and path are reported, never any other value."
                ),
                evidence=evidence,
                remediation=[
                    "Confirm each bundle is rebuilt from an updated upstream source, or unset the variable so the OS store is used.",
                    "Scan a bundle directly with: emudhra-trust-audit endpoint --bundle <path>",
                ],
            )
        )
    return findings, sources


def verification_findings(ctx: EndpointContext) -> List[Finding]:
    findings: List[Finding] = []
    for name, off_values in VERIFICATION_OFF_VARIABLES:
        raw = (ctx.env.get(name) or "").strip().lower()
        if raw and raw in off_values:
            findings.append(
                Finding(
                    id="ENDPOINT-VERIFICATION-DISABLED-ENV",
                    title="%s switches off TLS certificate verification" % name,
                    status=STATUS_KNOWN_INDICATOR,
                    severity="critical",
                    confidence="high",
                    action=ACTION_REQUIRED,
                    summary=(
                        "With this variable set, the affected client accepts any certificate, forged or "
                        "not. That is a larger problem than the CA incident this tool audits for, and it "
                        "is the first thing to fix."
                    ),
                    evidence=[Evidence(what=name, value=raw)],
                    remediation=[
                        "Unset %s in the shell profile, script or CI definition that sets it."
                        % name,
                        "Where a private CA is genuinely needed, point the matching *_CA_BUNDLE variable at it instead.",
                    ],
                    tags=[TAG_VERIFICATION_DISABLED],
                )
            )
    disabling_found = bool(findings)
    present = [name for name in OPAQUE_VARIABLES if ctx.env.get(name)]
    if present:
        findings.append(
            Finding(
                id="ENDPOINT-PROXY-CONFIGURED",
                title="An HTTP(S) proxy is configured",
                status=STATUS_KNOWN_INDICATOR,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "A TLS-inspecting proxy replaces server certificates, which changes what any online "
                    "test would show and can mask the real trust state. Values are not read or reported, "
                    "since a proxy URL often contains credentials."
                ),
                evidence=[Evidence(what="variable set", value=name) for name in present],
                remediation=[
                    "Interpret any online test result with the proxy in mind; prefer the offline store checks.",
                ],
            )
        )
    if not disabling_found:
        findings.append(
            Finding(
                id="ENDPOINT-VERIFICATION-ENV-CLEAN",
                title="No environment variable disables certificate verification",
                status=STATUS_NOT_FOUND,
                severity="pass",
                confidence="high",
                action=ACTION_NONE,
                summary="Checked %d variables known to disable or redirect verification."
                % (len(VERIFICATION_OFF_VARIABLES) + len(CA_OVERRIDE_VARIABLES)),
            )
        )
    return findings
