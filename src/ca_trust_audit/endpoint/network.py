"""Opt-in online check against a host the user names explicitly.

Off by default. It is never reached without ``--network-test HOST`` on the
command line, because connecting discloses the source address, TLS fingerprint
and client identity to whoever runs that host, and the result is distorted by
TLS-inspecting proxies, captive portals and DNS interference.

A handshake outcome on its own is never treated as a verdict: a rejection can
come from expiry, a name mismatch or a clock skew, and an acceptance can come
from a proxy substituting its own certificate. The chain is inspected for the
indicator SPKIs whenever it can be obtained.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from typing import List, Tuple

from ..certs import parse_bundle
from ..model import (
    ACTION_NONE,
    ACTION_REQUIRED,
    ACTION_REVIEW,
    STATUS_KNOWN_INDICATOR,
    STATUS_SUSPICIOUS,
    STATUS_UNABLE,
    Evidence,
    Finding,
)
from .context import EndpointContext

DEFAULT_PORT = 443
CONNECT_TIMEOUT = 10


def split_host(target: str) -> Tuple[str, int]:
    host = target.strip()
    port = DEFAULT_PORT
    if host.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", host)
        if not match:
            raise ValueError("invalid target")
        host, raw_port = match.groups()
        ipaddress.IPv6Address(host)
        port = int(raw_port) if raw_port else DEFAULT_PORT
    elif ":" in host:
        host, raw_port = host.rsplit(":", 1)
        if not raw_port.isdigit():
            raise ValueError("invalid port")
        port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    if ":" not in host and host and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise ValueError("invalid hostname")
    return host, port


def _handshake(host: str, port: int) -> Tuple[str, str]:
    """Return ``(outcome, detail)`` where outcome is accepted/rejected/error."""
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            return "accepted", "negotiated %s" % (tls.version() or "unknown version")
    except ssl.SSLCertVerificationError as error:
        return "rejected", "certificate verification failed: %s" % (
            error.verify_message or error.reason or "unspecified"
        )
    except ssl.SSLError as error:
        return "error", "TLS error: %s" % (error.reason or error)
    except (OSError, ValueError) as error:
        return "error", "connection failed: %s" % error


def _chain_spki(ctx: EndpointContext, host: str, port: int) -> Tuple[List[str], str]:
    """Fetch the presented chain with ``openssl s_client`` and return its SPKIs."""
    if ctx.runner.which("openssl") is None:
        return [], "openssl is not available, so the presented chain could not be inspected"
    result = ctx.runner.run(
        [
            "openssl",
            "s_client",
            "-connect",
            ("[%s]:%d" if ":" in host else "%s:%d") % (host, port),
            "-servername",
            host,
            "-showcerts",
        ],
        timeout=CONNECT_TIMEOUT + 10,
    )
    blob = (result.stdout or "").encode("utf-8", "replace")
    if b"BEGIN CERTIFICATE" not in blob:
        return [], result.error or "openssl returned no certificate"
    return [
        certificate.spki_sha256.lower() for certificate in parse_bundle(blob, source="s_client")
    ], ""


def audit(ctx: EndpointContext, target: str) -> List[Finding]:
    host, port = split_host(target)
    if not host:
        return [
            Finding(
                id="ENDPOINT-NETWORK-TEST-INVALID",
                title="No host was given for the network test",
                status=STATUS_UNABLE,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary="--network-test needs an explicit host; the audit never picks one for you.",
            )
        ]

    outcome, detail = _handshake(host, port)
    spkis, chain_problem = _chain_spki(ctx, host, port)
    compromised = ctx.data.compromised_spki
    matched = sorted({spki for spki in spkis if spki in compromised})

    evidence = [
        Evidence(what="target", value="%s:%d" % (host, port)),
        Evidence(what="handshake", value="%s - %s" % (outcome, detail)),
    ]
    if chain_problem:
        evidence.append(Evidence(what="chain inspection", value=chain_problem))
    else:
        evidence.append(Evidence(what="chain length", value="%d certificate(s)" % len(spkis)))
    for spki in matched:
        evidence.append(
            Evidence(
                what="compromised intermediate in presented chain",
                value="%s (%s)" % (compromised[spki].get("common_name", "?"), spki),
            )
        )

    references = ctx.data.incident_references

    if outcome == "accepted" and matched:
        return [
            Finding(
                id="ENDPOINT-NETWORK-ACCEPTED-COMPROMISED",
                title="A handshake succeeded and a separate connection presented an indicator",
                status=STATUS_KNOWN_INDICATOR,
                severity="critical",
                confidence="high",
                action=ACTION_REQUIRED,
                summary=(
                    "Python accepted one connection; a separate OpenSSL connection presented the key. "
                    "The two chains may differ, so effective acceptance is not established."
                ),
                evidence=evidence,
                remediation=[
                    "Update the OS trust store, browsers, runtimes and CLIs from their official channels, then restart them.",
                    "Re-run this test afterwards.",
                ],
                references=references,
                tags=["compromised-spki-present"],
            )
        ]
    if outcome == "accepted":
        return [
            Finding(
                id="ENDPOINT-NETWORK-ACCEPTED-UNVERIFIED",
                title="The handshake succeeded, but the chain could not be tied to an indicator",
                status=STATUS_SUSPICIOUS,
                severity="high",
                confidence="low",
                action=ACTION_REVIEW,
                summary=(
                    "A successful connection to a host that is meant to present a compromised chain is a "
                    "warning sign, but on its own it proves nothing: a TLS-inspecting proxy can replace "
                    "the certificate, and the host's configuration can change. Confirm with the offline "
                    "store checks."
                ),
                evidence=evidence,
                remediation=[
                    "Install openssl so the presented chain can be inspected, then re-run.",
                    "Compare with the offline findings in this same report before acting.",
                ],
                references=references,
            )
        ]
    if outcome == "rejected" and matched:
        return [
            Finding(
                id="ENDPOINT-NETWORK-REJECTED-COMPROMISED",
                title="A chain containing a compromised intermediate was rejected",
                status=STATUS_KNOWN_INDICATOR,
                severity="info",
                confidence="high",
                action=ACTION_NONE,
                summary=(
                    "A separate connection presented the indicator. Rejection may be due to expiry, "
                    "hostname or another error, and does not establish a block on this key."
                ),
                evidence=evidence,
                references=references,
                tags=["compromised-spki-blocklist-entry"],
            )
        ]
    if outcome == "rejected":
        return [
            Finding(
                id="ENDPOINT-NETWORK-REJECTED-UNATTRIBUTED",
                title="The handshake was rejected, but the reason cannot be attributed",
                status=STATUS_UNABLE,
                severity="info",
                confidence="medium",
                action=ACTION_NONE,
                summary=(
                    "A certificate error can also come from expiry, a name mismatch, a wrong clock or a "
                    "proxy. Do not read this as proof that the compromised keys are blocked."
                ),
                evidence=evidence,
                references=references,
            )
        ]
    return [
        Finding(
            id="ENDPOINT-NETWORK-TEST-FAILED",
            title="The network test could not be completed",
            status=STATUS_UNABLE,
            severity="info",
            confidence="high",
            action=ACTION_NONE,
            summary="No conclusion can be drawn from a connection that did not happen.",
            evidence=evidence,
        )
    ]
