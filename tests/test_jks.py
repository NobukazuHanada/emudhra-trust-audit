"""JKS truststore reading, including the refusal to touch key material."""

from __future__ import annotations

import base64
import struct
from typing import List, Tuple

import pytest

from ca_trust_audit import jks
from conftest import read_fixture_cert


def der_of(name: str) -> bytes:
    body = read_fixture_cert(name).split("-----")[2]
    return base64.b64decode("".join(body.split()))


def build_jks(
    trusted: List[Tuple[str, bytes]],
    *,
    version: int = 2,
    with_private_key: bool = False,
    magic: int = jks.MAGIC_JKS,
) -> bytes:
    """Assemble a JKS file the way the JDK writes one."""
    entries = b""
    count = 0
    if with_private_key:
        count += 1
        key_blob = b"\xde\xad\xbe\xef" * 8  # stands in for the protected key
        entries += struct.pack(">I", jks.TAG_PRIVATE_KEY)
        alias = b"mykey"
        entries += struct.pack(">H", len(alias)) + alias
        entries += struct.pack(">q", 0)
        entries += struct.pack(">I", len(key_blob)) + key_blob
        entries += struct.pack(">I", 1)  # one certificate in the chain
        chain_cert = der_of("unrelated")
        if version == 2:
            entries += struct.pack(">H", 5) + b"X.509"
        entries += struct.pack(">I", len(chain_cert)) + chain_cert
    for alias_text, der in trusted:
        count += 1
        alias = alias_text.encode("utf-8")
        entries += struct.pack(">I", jks.TAG_TRUSTED_CERT)
        entries += struct.pack(">H", len(alias)) + alias
        entries += struct.pack(">q", 0)
        if version == 2:
            entries += struct.pack(">H", 5) + b"X.509"
        entries += struct.pack(">I", len(der)) + der
    header = struct.pack(">IiI", magic, version, count)
    return header + entries + b"\x00" * 20  # trailing integrity digest


def test_reads_trusted_certificates() -> None:
    blob = build_jks(
        [("fixtureroot", der_of("related-root")), ("weak", der_of("weak-intermediate"))]
    )
    entries = jks.trusted_certificates(blob)
    assert [alias for alias, _ in entries] == ["fixtureroot", "weak"]
    assert entries[1][1] == der_of("weak-intermediate")


def test_private_key_entries_are_skipped_not_decoded() -> None:
    blob = build_jks([("weak", der_of("weak-intermediate"))], with_private_key=True)
    entries = jks.trusted_certificates(blob)
    assert [alias for alias, _ in entries] == ["weak"]


def test_version_1_keystores_have_no_certificate_type_field() -> None:
    blob = build_jks([("weak", der_of("weak-intermediate"))], version=1)
    assert len(jks.trusted_certificates(blob)) == 1


@pytest.mark.parametrize(
    "blob,expected",
    [
        (b"\xfe\xed\xfe\xed", "jks"),
        (b"\xce\xce\xce\xce", "jceks"),
        (b"\x30\x82\x04\x00", "pkcs12"),
        (b"abcd", "unknown"),
        (b"", "unknown"),
    ],
)
def test_format_detection(blob: bytes, expected: str) -> None:
    assert jks.detect_format(blob) == expected


def test_pkcs12_is_refused_rather_than_misparsed() -> None:
    with pytest.raises(jks.KeystoreError):
        jks.trusted_certificates(b"\x30\x82\x04\x00" + b"\x00" * 64)


def test_truncated_keystore_is_refused() -> None:
    blob = build_jks([("weak", der_of("weak-intermediate"))])
    with pytest.raises(jks.KeystoreError):
        jks.trusted_certificates(blob[:20])


def test_read_file_returns_none_for_unreadable(tmp_path) -> None:
    assert jks.read_file(tmp_path / "absent") is None
    broken = tmp_path / "cacerts"
    broken.write_bytes(b"\x30\x82\x04\x00")
    assert jks.read_file(broken) is None


def test_read_file_round_trip(tmp_path) -> None:
    path = tmp_path / "cacerts"
    path.write_bytes(build_jks([("weak", der_of("weak-intermediate"))]))
    entries = jks.read_file(path)
    assert entries is not None
    assert entries[0][0] == "weak"
