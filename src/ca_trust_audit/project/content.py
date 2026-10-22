"""Content checks: weakened TLS settings, vendored CA bundles, containers, CI."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..certs import parse_bundle
from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_SUSPICIOUS,
    STATUS_UNABLE,
    Evidence,
    Finding,
)
from ..util import read_regular_file
from . import parsers
from .scan import ProjectContext

MAX_MATCHES_PER_RULE = 20


DOC_SUFFIXES = (".md", ".rst", ".adoc", ".txt.example", ".example")
DOC_DIRECTORIES = ("docs/", "doc/", "documentation/", "skills/")


def _is_documentation(relative: str) -> bool:
    lowered = relative.lower()
    return lowered.endswith(DOC_SUFFIXES) or lowered.startswith(DOC_DIRECTORIES)


def insecure_findings(ctx: ProjectContext) -> List[Finding]:
    """Apply the textual ruleset from data/rules/insecure-tls.json."""
    rules = ctx.data.compiled_insecure_rules()
    data_version = str(ctx.data.insecure_rules.get("data_version", ""))
    hits: Dict[Tuple[str, bool], List[Tuple[str, int, str]]] = {}
    scanned = 0
    self_data = 0
    for entry in ctx.walk():
        if entry.too_large or not ctx.is_text_candidate(entry):
            continue
        text = ctx.read_text(entry.relative)
        if text is None:
            continue
        if ctx.is_self_data(entry.relative):
            # A vendored copy of this tool's own ruleset lists the patterns it
            # looks for; matching it against itself is noise, not a finding.
            self_data += 1
            continue
        scanned += 1
        documentation = _is_documentation(entry.relative)
        for rule in rules:
            if rule.path_hints and not any(
                hint.lower() in entry.relative.lower() for hint in rule.path_hints
            ):
                continue
            match = rule.regex.search(text)
            if match is None:
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            # One match per file per rule: the point is to name the file, not to
            # count occurrences.
            hits.setdefault((rule.id, documentation), []).append(
                (entry.relative, line_number, "matched rule " + rule.id + "; source text withheld")
            )

    findings: List[Finding] = []
    rules_by_id = {rule.id: rule for rule in rules}
    for (rule_id, documentation), matches in sorted(hits.items()):
        rule = rules_by_id[rule_id]
        if documentation:
            # Prose that mentions a switch is not the same as a switch. Reported,
            # but downgraded, never tagged, and never a verdict driver.
            status = STATUS_SUSPICIOUS
            severity = "low"
            confidence = "low"
            action = ACTION_REVIEW
            title = "%s (mentioned in documentation)" % rule.title
            summary = (
                "Matched inside a documentation file. It may be an instruction telling a reader to "
                "weaken verification, or it may be prose describing the problem. Read it before acting. "
            ) + rule.description
            tags: List[str] = []
        else:
            status = rule.status
            severity = rule.severity
            confidence = rule.confidence
            action = ACTION_REQUIRED if rule.status == STATUS_KNOWN_INDICATOR else ACTION_REVIEW
            title = rule.title
            summary = rule.description
            tags = list(rule.tags)
        findings.append(
            Finding(
                id="PROJECT-%s" % rule_id,
                title=title,
                status=status,
                severity=severity,
                confidence=confidence,
                action=action,
                summary=summary,
                evidence=[
                    Evidence(what="%s:%d" % (relative, line_number), value=line)
                    for relative, line_number, line in matches[:MAX_MATCHES_PER_RULE]
                ],
                remediation=list(rule.remediation),
                references=list(rule.references),
                tags=tags,
                locations=[relative for relative, _line, _text in matches[:MAX_MATCHES_PER_RULE]],
                data_version=data_version,
            )
        )
    if not hits:
        findings.append(
            Finding(
                id="PROJECT-TLS-SETTINGS-CLEAN",
                title="No weakened TLS setting was found in the files that were scanned",
                status=STATUS_NOT_FOUND,
                severity="pass",
                confidence="medium",
                action=ACTION_NONE,
                summary=(
                    "%d text file(s) were matched against %d rules; %d file(s) were skipped as a copy of "
                    "this tool's own ruleset and %d by .ca-trust-audit-ignore. Rules are textual: logic "
                    "that disables verification in a way no rule describes is not covered."
                    % (scanned, len(rules), self_data, len(ctx.ignored))
                ),
                data_version=data_version,
            )
        )
    return findings


def bundle_findings(ctx: ProjectContext) -> List[Finding]:
    """Scan CA bundles committed inside the repository for the indicator SPKIs."""
    inventory = ctx.data.inventory
    suffixes = tuple(str(value).lower() for value in inventory.get("ca_bundle_suffixes", []))
    hints = tuple(str(value).lower() for value in inventory.get("ca_bundle_name_hints", []))
    compromised = ctx.data.compromised_spki
    related = ctx.data.related_root_names

    scanned: List[Tuple[str, int]] = []
    matches: List[Evidence] = []
    related_hits: List[Evidence] = []
    for entry in ctx.walk():
        name = entry.relative.rsplit("/", 1)[-1].lower()
        if not name.endswith(suffixes) and not any(hint in name for hint in hints):
            continue
        if entry.too_large:
            continue
        blob = ctx.read_bytes(entry.relative)
        if not blob:
            continue
        certificates = parse_bundle(blob, source=entry.relative)
        if not certificates:
            ctx.problems.append("candidate certificate bundle could not be parsed")
            continue
        scanned.append((entry.relative, len(certificates)))
        for certificate in certificates:
            key = certificate.spki_sha256.lower()
            if key in compromised:
                matches.append(
                    Evidence(
                        what="compromised intermediate in a committed bundle",
                        value="%s (SPKI %s)" % (compromised[key].get("common_name", "?"), key),
                        source=entry.relative,
                    )
                )
            elif certificate.subject_cn.lower() in related:
                related_hits.append(
                    Evidence(
                        what="related root in a committed bundle",
                        value=certificate.subject_cn,
                        source=entry.relative,
                    )
                )

    findings: List[Finding] = []
    if matches:
        findings.append(
            Finding(
                id="PROJECT-BUNDLE-COMPROMISED-SPKI",
                title="A CA bundle committed to this repository contains a compromised intermediate",
                status=STATUS_KNOWN_INDICATOR,
                severity="critical",
                confidence="high",
                action=ACTION_REQUIRED,
                summary=(
                    "The bundle contains a compromised key. Review whether production clients use it; "
                    "presence alone does not prove a client accepts a forged chain."
                ),
                evidence=matches[:MAX_MATCHES_PER_RULE],
                remediation=[
                    "Regenerate the bundle from an updated upstream source (for example a fixed ca-certificates or certifi release).",
                    "Rebuild and redeploy every image or artefact that embedded the old bundle.",
                ],
                references=ctx.data.incident_references,
                tags=["compromised-spki-present"],
                locations=sorted({item.source for item in matches}),
                data_version=str(ctx.data.incident.get("data_version", "")),
            )
        )
    elif scanned:
        findings.append(
            Finding(
                id="PROJECT-BUNDLE-CLEAN",
                title="Committed CA bundles carry none of the compromised intermediates",
                status=STATUS_NOT_FOUND,
                severity="pass",
                confidence="high",
                action=ACTION_NONE,
                summary="A bundle without the compromised intermediate can still trust the root that signed it.",
                evidence=[
                    Evidence(what=relative, value="%d certificate(s)" % count)
                    for relative, count in scanned[:MAX_MATCHES_PER_RULE]
                ],
                locations=[relative for relative, _count in scanned[:MAX_MATCHES_PER_RULE]],
            )
        )
    if related_hits:
        findings.append(
            Finding(
                id="PROJECT-BUNDLE-RELATED-ROOT",
                title="A committed CA bundle contains a related root (expected, not a risk by itself)",
                status=STATUS_KNOWN_INDICATOR,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "These roots are widely trusted and are normally kept while the compromised keys are "
                    "blocked. Do not strip them on the strength of this line alone."
                ),
                evidence=related_hits[:MAX_MATCHES_PER_RULE],
                references=ctx.data.incident_references,
                locations=sorted({item.source for item in related_hits}),
            )
        )
    return findings


_FROM = re.compile(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE | re.MULTILINE)


def container_findings(ctx: ProjectContext) -> List[Finding]:
    if not ctx.include_containers:
        return []
    inventory = ctx.data.inventory
    patterns = [
        re.compile(value, re.IGNORECASE)
        for value in inventory.get("container_ca_update_patterns", [])
    ]
    files = ctx.match(inventory.get("container_files", []))
    if not files:
        return []
    findings: List[Finding] = []
    without_update: List[Evidence] = []
    pinned_digests: List[Evidence] = []
    for item in files:
        text = ctx.read_text(item.relative)
        if text is None:
            continue
        images = [match.group("image") for match in _FROM.finditer(text)]
        refreshes = any(pattern.search(text) for pattern in patterns)
        if images and not refreshes:
            without_update.append(
                Evidence(
                    what="no CA refresh step",
                    value="%d base image reference(s); values withheld" % len(images),
                    source=item.relative,
                )
            )
        for image in images:
            if "@sha256:" in image:
                pinned_digests.append(
                    Evidence(
                        what="digest-pinned base image",
                        value="digest present; image withheld",
                        source=item.relative,
                    )
                )
    if without_update:
        findings.append(
            Finding(
                id="PROJECT-CONTAINER-NO-CA-REFRESH",
                title="A container definition does not refresh CA certificates",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="medium",
                action=ACTION_REVIEW,
                summary=(
                    "The image inherits whatever CA bundle its base image shipped. If that base image "
                    "predates the fix and the image is not rebuilt, the container keeps trusting the "
                    "compromised intermediates even on a fully patched host."
                ),
                evidence=without_update[:MAX_MATCHES_PER_RULE],
                remediation=[
                    "Rebuild against a current base image, or add an explicit CA package update in the build.",
                    "Redeploy running containers after rebuilding: a running container keeps its old bundle.",
                ],
                locations=sorted({item.source for item in without_update}),
                data_version=str(inventory.get("data_version", "")),
            )
        )
    if pinned_digests:
        findings.append(
            Finding(
                id="PROJECT-CONTAINER-DIGEST-PINNED",
                title="A base image is pinned by digest",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary=(
                    "A digest pin freezes the CA bundle inside that image. Rebuilding will not pick up a "
                    "fixed bundle until the digest is updated."
                ),
                evidence=pinned_digests[:MAX_MATCHES_PER_RULE],
                remediation=[
                    "Update the pinned digest to an image published after the fix, then rebuild."
                ],
                locations=sorted({item.source for item in pinned_digests}),
            )
        )
    return findings


_ACTION_VERSION = re.compile(
    r"(?P<key>node-version|python-version|go-version|java-version|dotnet-version)\s*:\s*['\"]?(?P<version>[0-9][^'\"\s]*)",
    re.IGNORECASE,
)
_CONTAINER_IMAGE = re.compile(
    r"^\s*image\s*:\s*['\"]?(?P<image>[^'\"\s]+)", re.IGNORECASE | re.MULTILINE
)


def ci_findings(ctx: ProjectContext) -> List[Finding]:
    files = ctx.match(ctx.data.inventory.get("ci_files", []))
    if not files:
        return []
    evidence: List[Evidence] = []
    for item in files:
        text = ctx.read_text(item.relative)
        if text is None:
            continue
        for match in _ACTION_VERSION.finditer(text):
            evidence.append(
                Evidence(
                    what="pinned runtime",
                    value="%s %s"
                    % (
                        match.group("key"),
                        parsers._dep("", match.group("version"), "", "", "").version,
                    ),
                    source=item.relative,
                )
            )
        for _match in _CONTAINER_IMAGE.finditer(text):
            evidence.append(
                Evidence(
                    what="CI container image",
                    value="image reference present; value withheld",
                    source=item.relative,
                )
            )
    if not evidence:
        return []
    return [
        Finding(
            id="PROJECT-CI-PINNED-RUNTIME",
            title="CI pins runtime versions or container images",
            status=STATUS_UNABLE,
            severity="info",
            confidence="high",
            action=ACTION_NONE,
            summary=(
                "A pinned runtime or image in CI can keep using a pre-fix CA bundle long after developer "
                "machines are updated. Compare each pin against the fixed versions in data/policies/."
            ),
            evidence=evidence[:MAX_MATCHES_PER_RULE],
            locations=sorted({item.source for item in evidence}),
        )
    ]


def external_bundle_finding(ctx: ProjectContext, path: str) -> Optional[Finding]:
    """``--scan-bundle``: check one bundle named by the user."""
    target = Path(path)
    try:
        blob = read_regular_file(target)
    except OSError as error:
        return Finding(
            id="PROJECT-SCAN-BUNDLE-UNREADABLE",
            title="The bundle given to --scan-bundle could not be read",
            status=STATUS_UNABLE,
            severity="medium",
            confidence="high",
            action=ACTION_REVIEW,
            summary=str(error.strerror or error),
            evidence=[Evidence(what="path", value=str(target))],
        )
    certificates = parse_bundle(blob, source=str(target))
    compromised = ctx.data.compromised_spki
    matches = [
        Evidence(
            what="compromised intermediate",
            value="%s (SPKI %s)"
            % (compromised[c.spki_sha256.lower()].get("common_name", "?"), c.spki_sha256),
            source=str(target),
        )
        for c in certificates
        if c.spki_sha256.lower() in compromised
    ]
    if matches:
        return Finding(
            id="PROJECT-SCAN-BUNDLE-COMPROMISED",
            title="The scanned bundle contains a compromised intermediate",
            status=STATUS_KNOWN_INDICATOR,
            severity="critical",
            confidence="high",
            action=ACTION_REQUIRED,
            summary="An exact key match was found; effective client acceptance is not established.",
            evidence=matches,
            remediation=[
                "Rebuild this bundle from an updated upstream source and redeploy whatever reads it."
            ],
            references=ctx.data.incident_references,
            tags=["compromised-spki-present"],
        )
    return Finding(
        id="PROJECT-SCAN-BUNDLE-CLEAN",
        title="The scanned bundle contains none of the compromised intermediates",
        status=STATUS_NOT_FOUND if certificates else STATUS_UNABLE,
        severity="pass" if certificates else "medium",
        confidence="high",
        action=ACTION_NONE if certificates else ACTION_REVIEW,
        summary=(
            "%d certificate(s) parsed." % len(certificates)
            if certificates
            else "No certificate could be parsed out of this file."
        ),
        evidence=[Evidence(what="path", value=str(target))],
    )
