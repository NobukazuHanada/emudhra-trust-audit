"""Trust store enumeration and SPKI matching.

A "trust source" is any place a client reads trust anchors from. Each source
carries a role, because the same certificate means opposite things depending on
where it was found:

``trusted``      a client would accept a chain through anything in here.
``distrusted``   an explicit block list (Windows ``Disallowed``, p11-kit
                 blocklist directories).
``source-pool``  an on-disk pool that is only trusted once selected by
                 configuration, so presence alone proves nothing.
``independent``  a runtime's own store, unaffected by OS updates.
``override``     a bundle selected by an environment variable or client setting.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from ..certs import ParsedCertificate, parse_bundle, parse_bundle_file
from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_NOT_FOUND,
    STATUS_UNABLE,
    TAG_INDEPENDENT_STORE,
    TAG_SPKI_ABSENT,
    Evidence,
    Finding,
)
from ..util import read_regular_file
from .context import EndpointContext

ROLE_TRUSTED = "trusted"
ROLE_DISTRUSTED = "distrusted"
ROLE_SOURCE_POOL = "source-pool"
ROLE_INDEPENDENT = "independent"
ROLE_OVERRIDE = "override"

CERT_SUFFIXES = (".pem", ".crt", ".cer", ".cert", ".0")
MAX_DIR_FILES = 5000

LINUX_BUNDLE_FILES = (
    ("/etc/ssl/certs/ca-certificates.crt", "Debian/Ubuntu/Arch/Alpine OS bundle"),
    ("/etc/pki/tls/certs/ca-bundle.crt", "RHEL/Fedora OS bundle"),
    ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "p11-kit extracted TLS bundle"),
    ("/etc/ssl/ca-bundle.pem", "openSUSE OS bundle"),
    ("/var/lib/ca-certificates/ca-bundle.pem", "openSUSE generated bundle"),
    ("/etc/ssl/cert.pem", "OpenSSL default cert.pem"),
)

LINUX_TRUSTED_DIRS = (
    ("/etc/ssl/certs", "OpenSSL hashed trust directory"),
    ("/usr/local/share/ca-certificates", "locally added anchors"),
    ("/etc/pki/ca-trust/source/anchors", "p11-kit local anchors"),
    ("/etc/ca-certificates/trust-source/anchors", "Arch local anchors"),
)

LINUX_SOURCE_DIRS = (("/usr/share/ca-certificates", "distribution certificate pool"),)

LINUX_BLOCKLIST_DIRS = (
    ("/etc/pki/ca-trust/source/blocklist", "p11-kit blocklist"),
    ("/etc/ca-certificates/trust-source/blacklist", "Arch blocklist"),
)

DARWIN_KEYCHAINS = (
    ("/System/Library/Keychains/SystemRootCertificates.keychain", "System Roots keychain"),
    ("/Library/Keychains/System.keychain", "System keychain"),
)

DARWIN_BUNDLE_FILES = (
    ("/etc/ssl/cert.pem", "OpenSSL/LibreSSL cert.pem used by command line clients"),
    ("/opt/homebrew/etc/ca-certificates/cert.pem", "Homebrew ca-certificates (Apple silicon)"),
    ("/usr/local/etc/ca-certificates/cert.pem", "Homebrew ca-certificates (Intel)"),
    ("/opt/homebrew/etc/openssl@3/cert.pem", "Homebrew openssl@3 bundle (Apple silicon)"),
    ("/usr/local/etc/openssl@3/cert.pem", "Homebrew openssl@3 bundle (Intel)"),
)

WINDOWS_STORE_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "foreach ($store in @("
    "'Cert:\\LocalMachine\\Root','Cert:\\LocalMachine\\CA','Cert:\\LocalMachine\\Disallowed',"
    "'Cert:\\CurrentUser\\Root','Cert:\\CurrentUser\\CA','Cert:\\CurrentUser\\Disallowed'"
    ")) { foreach ($certificate in Get-ChildItem -Path $store) {"
    "Write-Output ($store + '|' + [Convert]::ToBase64String($certificate.RawData)) } }"
)

WINDOWS_ROOT_UPDATE_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$key = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot';"
    "Write-Output ('DisableRootAutoUpdate=' + [string]$key.DisableRootAutoUpdate);"
    "$ca = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\DisallowedCertEncodedCtl';"
    "Write-Output ('DisallowedCtlPresent=' + [string]($null -ne $ca))"
)


@dataclasses.dataclass
class TrustSource:
    label: str
    location: str
    role: str
    certificates: List[ParsedCertificate] = dataclasses.field(default_factory=list)
    readable: bool = True
    detail: str = ""

    @property
    def count(self) -> int:
        return len(self.certificates)


def _bundle_source(
    ctx: EndpointContext, absolute: str, label: str, role: str
) -> Optional[TrustSource]:
    path = ctx.path(absolute)
    if not path.exists() or path.is_dir():
        return None
    try:
        blob = read_regular_file(path)
    except OSError as error:
        return TrustSource(
            label=label,
            location=ctx.show(absolute),
            role=role,
            readable=False,
            detail="unreadable: %s" % (error.strerror or error),
        )
    certificates = parse_bundle(blob, source=ctx.show(absolute))
    if not certificates:
        return TrustSource(
            label=label,
            location=ctx.show(absolute),
            role=role,
            readable=False,
            detail="no parseable certificate in %d bytes" % len(blob),
        )
    return TrustSource(
        label=label, location=ctx.show(absolute), role=role, certificates=certificates
    )


def _directory_source(
    ctx: EndpointContext, absolute: str, label: str, role: str
) -> Optional[TrustSource]:
    path = ctx.path(absolute)
    if not path.is_dir():
        return None
    certificates: List[ParsedCertificate] = []
    seen = 0
    incomplete = False
    try:
        entries = sorted(path.iterdir())
    except OSError as error:
        return TrustSource(
            label=label,
            location=ctx.show(absolute),
            role=role,
            readable=False,
            detail="unreadable: %s" % error.strerror,
        )
    for entry in entries:
        if seen >= MAX_DIR_FILES:
            incomplete = True
            break
        if entry.is_dir():
            continue
        if entry.suffix.lower() not in CERT_SUFFIXES:
            continue
        seen += 1
        parsed = parse_bundle_file(entry, source=ctx.show(entry))
        if not parsed:
            incomplete = True
        certificates.extend(parsed)
    return TrustSource(
        label=label,
        location=ctx.show(absolute),
        role=role,
        certificates=certificates,
        readable=not incomplete,
        detail="some certificates were unreadable or the directory limit was reached"
        if incomplete
        else "",
    )


def collect_linux_sources(ctx: EndpointContext) -> List[TrustSource]:
    sources: List[TrustSource] = []
    for absolute, label in LINUX_BUNDLE_FILES:
        source = _bundle_source(ctx, absolute, label, ROLE_TRUSTED)
        if source:
            sources.append(source)
    for absolute, label in LINUX_TRUSTED_DIRS:
        source = _directory_source(ctx, absolute, label, ROLE_TRUSTED)
        if source:
            sources.append(source)
    for absolute, label in LINUX_SOURCE_DIRS:
        source = _directory_source(ctx, absolute, label, ROLE_SOURCE_POOL)
        if source:
            sources.append(source)
    for absolute, label in LINUX_BLOCKLIST_DIRS:
        source = _directory_source(ctx, absolute, label, ROLE_DISTRUSTED)
        if source:
            sources.append(source)
    openssl_dir = _openssl_dir(ctx)
    if openssl_dir:
        for candidate, label in (
            (openssl_dir + "/cert.pem", "OpenSSL OPENSSLDIR cert.pem"),
            (openssl_dir + "/certs", "OpenSSL OPENSSLDIR certs directory"),
        ):
            source = _bundle_source(ctx, candidate, label, ROLE_TRUSTED) or _directory_source(
                ctx, candidate, label, ROLE_TRUSTED
            )
            if source and not any(existing.location == source.location for existing in sources):
                sources.append(source)
    return sources


def collect_darwin_sources(ctx: EndpointContext) -> List[TrustSource]:
    sources: List[TrustSource] = []
    keychains = list(DARWIN_KEYCHAINS)
    home = ctx.env.get("HOME")
    if ctx.include_user_stores and home:
        keychains.append((home + "/Library/Keychains/login.keychain-db", "login keychain"))
    for absolute, label in keychains:
        if not ctx.path(absolute).exists():
            continue
        result = ctx.runner.run(["security", "find-certificate", "-a", "-p", absolute])
        if not result.ok:
            sources.append(
                TrustSource(
                    label=label,
                    location=ctx.show(absolute),
                    role=ROLE_TRUSTED,
                    readable=False,
                    detail=result.error or "security exited %d" % result.returncode,
                )
            )
            continue
        sources.append(
            TrustSource(
                label=label,
                location=ctx.show(absolute),
                role=ROLE_TRUSTED,
                certificates=parse_bundle(result.stdout.encode("utf-8", "replace"), source=label),
            )
        )
    for absolute, label in DARWIN_BUNDLE_FILES:
        source = _bundle_source(ctx, absolute, label, ROLE_TRUSTED)
        if source:
            sources.append(source)
    return sources


def collect_windows_sources(ctx: EndpointContext) -> List[TrustSource]:
    script = WINDOWS_STORE_SCRIPT
    if not ctx.include_user_stores:
        script = script.replace(
            ",'Cert:\\CurrentUser\\Root','Cert:\\CurrentUser\\CA','Cert:\\CurrentUser\\Disallowed'",
            "",
        )
    result = ctx.runner.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=120,
    )
    if not result.ok:
        return [
            TrustSource(
                label="Windows certificate stores",
                location="Cert:\\LocalMachine and Cert:\\CurrentUser",
                role=ROLE_TRUSTED,
                readable=False,
                detail=result.error or "powershell exited %d" % result.returncode,
            )
        ]
    grouped: Dict[str, List[ParsedCertificate]] = {}
    import base64
    import binascii

    from ..certs import CertificateParseError, parse_certificate

    for line in result.stdout.splitlines():
        if "|" not in line:
            continue
        store, _, encoded = line.partition("|")
        store = store.strip()
        if not ctx.include_user_stores and "currentuser" in store.lower():
            continue
        try:
            der = base64.b64decode(encoded.strip(), validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            grouped.setdefault(store, []).append(parse_certificate(der, source=store))
        except CertificateParseError:
            continue
    sources: List[TrustSource] = []
    for store, certificates in sorted(grouped.items()):
        role = ROLE_DISTRUSTED if store.lower().endswith("disallowed") else ROLE_TRUSTED
        sources.append(
            TrustSource(
                label="Windows store %s" % store,
                location=store,
                role=role,
                certificates=certificates,
            )
        )
    return sources


def _openssl_dir(ctx: EndpointContext) -> str:
    result = ctx.runner.run(["openssl", "version", "-d"])
    if not result.ok:
        return ""
    match = re.search(r'OPENSSLDIR:\s*"([^"]+)"', result.stdout)
    return match.group(1) if match else ""


def collect_os_sources(ctx: EndpointContext) -> List[TrustSource]:
    if ctx.is_linux:
        return collect_linux_sources(ctx)
    if ctx.is_darwin:
        return collect_darwin_sources(ctx)
    if ctx.is_windows:
        return collect_windows_sources(ctx)
    return []


def extra_bundle_sources(ctx: EndpointContext) -> List[TrustSource]:
    sources: List[TrustSource] = []
    for path in ctx.extra_bundles:
        target = Path(path)
        if target.is_dir():
            source = _directory_source(
                ctx, str(target), "user-supplied bundle directory", ROLE_OVERRIDE
            )
        elif target.exists():
            certificates = parse_bundle_file(target, source=ctx.show(target))
            source = TrustSource(
                label="user-supplied bundle",
                location=ctx.show(target),
                role=ROLE_OVERRIDE,
                certificates=certificates,
                readable=bool(certificates),
                detail="" if certificates else "no parseable certificate found",
            )
        else:
            source = TrustSource(
                label="user-supplied bundle",
                location=ctx.show(target),
                role=ROLE_OVERRIDE,
                readable=False,
                detail="path does not exist",
            )
        sources.append(source)
    return sources


def _matches(ctx: EndpointContext, sources: Sequence[TrustSource]) -> Dict[str, List[TrustSource]]:
    compromised = ctx.data.compromised_spki
    found: Dict[str, List[TrustSource]] = {}
    for source in sources:
        for certificate in source.certificates:
            key = certificate.spki_sha256.lower()
            if key in compromised:
                found.setdefault(key, []).append(source)
    return found


def _related_roots(ctx: EndpointContext, sources: Sequence[TrustSource]) -> List[Evidence]:
    names = ctx.data.related_root_names
    evidence: List[Evidence] = []
    seen = set()
    for source in sources:
        if source.role not in (ROLE_TRUSTED, ROLE_INDEPENDENT, ROLE_OVERRIDE):
            continue
        for certificate in source.certificates:
            key = (certificate.subject_cn.lower(), source.location)
            if certificate.subject_cn.lower() in names and key not in seen:
                seen.add(key)
                evidence.append(
                    Evidence(
                        what="related root present",
                        value="%s (%s)"
                        % (certificate.subject_cn, names[certificate.subject_cn.lower()]["role"]),
                        source=source.location,
                    )
                )
    return evidence


def evaluate_sources(ctx: EndpointContext, sources: Sequence[TrustSource]) -> List[Finding]:
    """Turn collected trust sources into findings."""
    findings: List[Finding] = []
    compromised = ctx.data.compromised_spki
    data_version = str(ctx.data.incident.get("data_version", ""))
    references = ctx.data.incident_references
    matches = _matches(ctx, sources)

    trusted_hits: Dict[str, List[TrustSource]] = {}
    distrusted_hits: Dict[str, List[TrustSource]] = {}
    pool_hits: Dict[str, List[TrustSource]] = {}
    for key, hit_sources in matches.items():
        for source in hit_sources:
            if source.role == ROLE_DISTRUSTED:
                distrusted_hits.setdefault(key, []).append(source)
            elif source.role == ROLE_SOURCE_POOL:
                pool_hits.setdefault(key, []).append(source)
            else:
                trusted_hits.setdefault(key, []).append(source)

    for key, hit_sources in sorted(trusted_hits.items()):
        entry = compromised[key]
        findings.append(
            Finding(
                id="ENDPOINT-SPKI-TRUSTED",
                title="Compromised intermediate CA key is present in a trust source a client reads",
                status=STATUS_KNOWN_INDICATOR,
                severity="critical" if entry.get("usage") == "tls" else "high",
                confidence="high",
                action=ACTION_REQUIRED,
                summary=(
                    "%s (%s use) was found in %d trust source(s). This is an exact key match, "
                    "not proof of acceptance: client policy and revocation may still reject it."
                    % (
                        entry.get("common_name", "unknown CA"),
                        entry.get("usage", "unknown"),
                        len(hit_sources),
                    )
                ),
                evidence=[Evidence(what="SPKI SHA-256", value=key)]
                + [
                    Evidence(
                        what="found in %s" % source.label, value=source.role, source=source.location
                    )
                    for source in hit_sources
                ],
                remediation=[
                    "Update the component that owns this store from its official channel, then restart the processes that use it.",
                    "If the store is a hand-maintained bundle, rebuild it from an updated upstream bundle.",
                    "Do not disable TLS verification to work around a certificate error.",
                ],
                references=references,
                tags=["compromised-spki-present"],
                data_version=data_version,
            )
        )

    for key, hit_sources in sorted(distrusted_hits.items()):
        entry = compromised[key]
        findings.append(
            Finding(
                id="ENDPOINT-SPKI-DISTRUSTED",
                title="Compromised intermediate CA key is explicitly distrusted",
                status=STATUS_KNOWN_INDICATOR,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary="%s was found in an explicit block list, which is the desired state."
                % entry.get("common_name", "unknown CA"),
                evidence=[Evidence(what="SPKI SHA-256", value=key)]
                + [
                    Evidence(what="block list", value=source.label, source=source.location)
                    for source in hit_sources
                ],
                references=references,
                tags=["compromised-spki-blocklist-entry"],
                data_version=data_version,
            )
        )

    for key, hit_sources in sorted(pool_hits.items()):
        if key in trusted_hits or key in distrusted_hits:
            continue
        entry = compromised[key]
        findings.append(
            Finding(
                id="ENDPOINT-SPKI-IN-SOURCE-POOL",
                title="Compromised intermediate is present in a certificate pool, trust state undetermined",
                status=STATUS_KNOWN_INDICATOR,
                severity="medium",
                confidence="medium",
                action=ACTION_REVIEW,
                summary=(
                    "%s is on disk in a pool that is only trusted when configuration selects it. "
                    "Presence here is not proof of trust; check the selecting configuration."
                    % entry.get("common_name", "unknown CA")
                ),
                evidence=[Evidence(what="SPKI SHA-256", value=key)]
                + [
                    Evidence(what="pool", value=source.label, source=source.location)
                    for source in hit_sources
                ],
                remediation=[
                    "Check whether the pool entry is enabled (for example in /etc/ca-certificates.conf) and update the package that owns it.",
                ],
                references=references,
                tags=[],
                data_version=data_version,
            )
        )

    # A store that yielded no certificate is evidence of nothing: an empty local
    # anchors directory must not count as "checked and clean".
    readable_trusted = [
        source
        for source in sources
        if source.readable
        and source.count > 0
        and source.role in (ROLE_TRUSTED, ROLE_INDEPENDENT, ROLE_OVERRIDE)
    ]
    unreadable = [source for source in sources if not source.readable]

    if not matches and readable_trusted:
        findings.append(
            Finding(
                id="ENDPOINT-SPKI-ABSENT",
                title="No compromised intermediate found in the trust sources that were read",
                status=STATUS_NOT_FOUND,
                severity="pass",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "%d trust source(s) holding %d certificate(s) were parsed and none carried one of the %d "
                    "compromised public keys. This does not prove a forged chain would be rejected: a server "
                    "can present the compromised intermediate itself, so the decisive factor is whether the "
                    "issuing root still vouches for it."
                    % (
                        len(readable_trusted),
                        sum(source.count for source in readable_trusted),
                        len(compromised),
                    )
                ),
                evidence=[
                    Evidence(
                        what=source.label,
                        value="%d certificates" % source.count,
                        source=source.location,
                    )
                    for source in readable_trusted
                ],
                references=references,
                tags=[TAG_SPKI_ABSENT],
                data_version=data_version,
            )
        )

    if unreadable:
        findings.append(
            Finding(
                id="ENDPOINT-STORE-UNREADABLE",
                title="One or more trust sources could not be read",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary="The audit could not read these stores, so their contents are unknown.",
                evidence=[
                    Evidence(what=source.label, value=source.detail, source=source.location)
                    for source in unreadable
                ],
                remediation=[
                    "Re-run the audit as a user that can read the store, or inspect it with the platform's own tool.",
                    "On Windows, Cert:\\LocalMachine stores need an elevated PowerShell session to enumerate fully.",
                ],
                references=[],
                tags=[],
                data_version=data_version,
            )
        )

    if not readable_trusted and not unreadable:
        findings.append(
            Finding(
                id="ENDPOINT-NO-STORE-FOUND",
                title="No trust source was located for this platform",
                status=STATUS_UNABLE,
                severity="medium",
                confidence="high",
                action=ACTION_REVIEW,
                summary="None of the known trust store locations exist here, so nothing could be compared.",
                remediation=[
                    "Check the platform is supported, or pass --bundle with the CA bundle this machine actually uses.",
                ],
                tags=[],
                data_version=data_version,
            )
        )

    root_evidence = _related_roots(ctx, sources)
    if root_evidence:
        findings.append(
            Finding(
                id="ENDPOINT-RELATED-ROOT-PRESENT",
                title="Related root CA is present (expected, not a risk by itself)",
                status=STATUS_KNOWN_INDICATOR,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "These roots issued or cross-signed the affected intermediates. Clients block the "
                    "compromised keys without removing the root, so a trusted root here is normal and must "
                    "not be treated as exposure. Removing it by hand can break unrelated certificates."
                ),
                evidence=root_evidence,
                references=references,
                tags=[],
                data_version=data_version,
            )
        )

    independent = [
        source for source in sources if source.role == ROLE_INDEPENDENT and source.readable
    ]
    if independent:
        findings.append(
            Finding(
                id="ENDPOINT-INDEPENDENT-STORES",
                title="Runtimes with their own trust store were found",
                status=STATUS_NOT_FOUND if not matches else STATUS_KNOWN_INDICATOR,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "These stores are not updated by an operating system patch. Each one has to be "
                    "updated through its own channel."
                ),
                evidence=[
                    Evidence(
                        what=source.label,
                        value="%d certificates" % source.count,
                        source=source.location,
                    )
                    for source in independent
                ],
                tags=[TAG_INDEPENDENT_STORE],
                data_version=data_version,
            )
        )

    return findings


def windows_root_update_findings(ctx: EndpointContext) -> List[Finding]:
    """Check that automatic certificate trust list updates are not policy-disabled."""
    if not ctx.is_windows:
        return []
    result = ctx.runner.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_ROOT_UPDATE_SCRIPT]
    )
    if not result.ok:
        return [
            Finding(
                id="ENDPOINT-WINDOWS-CTL-UNKNOWN",
                title="Automatic certificate trust list update policy could not be read",
                status=STATUS_UNABLE,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary="The AuthRoot policy key could not be queried, so the update path is unverified.",
                evidence=[Evidence(what="command", value=result.error or "non-zero exit")],
                remediation=[
                    "Confirm with your administrator that automatic root/CTL updates are permitted, or verify Windows Update is current.",
                ],
            )
        ]
    disabled = re.search(r"DisableRootAutoUpdate=(\d+)", result.stdout)
    if disabled and disabled.group(1) not in ("", "0"):
        return [
            Finding(
                id="ENDPOINT-WINDOWS-CTL-DISABLED",
                title="Automatic certificate trust list updates are disabled by policy",
                status=STATUS_KNOWN_INDICATOR,
                severity="high",
                confidence="high",
                action=ACTION_REQUIRED,
                summary=(
                    "With DisableRootAutoUpdate set, this machine does not receive the untrusted "
                    "certificate list that normally blocks the compromised intermediates."
                ),
                evidence=[
                    Evidence(
                        what="policy value",
                        value="DisableRootAutoUpdate=%s" % disabled.group(1),
                        source="HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot",
                    )
                ],
                remediation=[
                    "Ask the administrator who owns this policy to allow automatic CTL updates, or to distribute the untrusted CTL through the managed channel.",
                    "On a deliberately offline machine, importing the 16 impacted certificates into LocalMachine\\Disallowed is the documented workaround - do it under change control, never automatically.",
                ],
                tags=[],
            )
        ]
    return [
        Finding(
            id="ENDPOINT-WINDOWS-CTL-ENABLED",
            title="Automatic certificate trust list updates are not disabled by policy",
            status=STATUS_NOT_FOUND,
            severity="pass",
            confidence="medium",
            action=ACTION_NONE,
            summary=(
                "No DisableRootAutoUpdate policy was found. A machine that reaches Windows Update "
                "normally receives the untrusted certificate list that blocks these keys; this check "
                "reads the policy only and does not prove the list has already been applied."
            ),
        )
    ]


def linux_ca_conf_findings(ctx: EndpointContext) -> List[Finding]:
    """Report disabled entries in /etc/ca-certificates.conf for the related roots."""
    if not ctx.is_linux:
        return []
    path = ctx.path("/etc/ca-certificates.conf")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names = [_token(name) for name in ctx.data.related_root_names]
    evidence: List[Evidence] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lowered = _token(stripped)
        if any(name and name in lowered for name in names):
            evidence.append(
                Evidence(
                    what="disabled" if stripped.startswith("!") else "enabled",
                    value=stripped.lstrip("!"),
                    source=ctx.show("/etc/ca-certificates.conf"),
                )
            )
    if not evidence:
        return []
    return [
        Finding(
            id="ENDPOINT-LINUX-CA-CONF",
            title="Related root entries in /etc/ca-certificates.conf",
            status=STATUS_KNOWN_INDICATOR,
            severity="info",
            confidence="medium",
            action=ACTION_NONE,
            summary=(
                "Lines prefixed with '!' are excluded from the generated bundle. This is contextual "
                "evidence about the distribution's handling, not a verdict."
            ),
            evidence=evidence,
            references=ctx.data.incident_references,
        )
    ]


def _token(name: str) -> str:
    """Collapse a CA name to comparable characters: 'emSign Root TLS CA - G3' -> 'emsignroottlscag3'."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def all_certificates(sources: Iterable[TrustSource]) -> List[ParsedCertificate]:
    out: List[ParsedCertificate] = []
    for source in sources:
        out.extend(source.certificates)
    return out
