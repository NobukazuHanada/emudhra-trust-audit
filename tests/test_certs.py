from __future__ import annotations

import base64
import hashlib

import pytest

from ca_trust_audit import certs
from conftest import FIXTURE_CERTS, read_fixture_cert


def der_of(name: str) -> bytes:
    body = read_fixture_cert(name).split("-----")[2]
    return base64.b64decode("".join(body.split()))


def test_parses_subject_and_fingerprints() -> None:
    der = der_of("weak-intermediate")
    parsed = certs.parse_certificate(der)
    assert parsed.subject_cn == "Fixture Weak Intermediate CA - T1"
    assert parsed.subject_o == "ca-trust-audit test fixtures"
    assert parsed.sha256 == hashlib.sha256(der).hexdigest()
    assert len(parsed.spki_sha256) == 64
    assert parsed.spki_sha256 != parsed.sha256


def test_spki_is_the_public_key_not_the_certificate() -> None:
    """Two certificates with different bodies but the same key share an SPKI.

    That is the whole reason SPKI is the primary match key: the incident's
    directly signed and cross-signed certificates differ, the key does not.
    """
    parsed = certs.parse_certificate(der_of("weak-intermediate"))
    other = certs.parse_certificate(der_of("unrelated"))
    assert parsed.spki_sha256 != other.spki_sha256


def test_parse_bundle_reads_every_pem_block() -> None:
    blob = (read_fixture_cert("weak-intermediate") + read_fixture_cert("unrelated")).encode()
    parsed = certs.parse_bundle(blob, source="bundle")
    assert len(parsed) == 2
    assert [item.index for item in parsed] == [0, 1]
    assert all(item.source == "bundle" for item in parsed)


def test_parse_bundle_accepts_raw_der() -> None:
    parsed = certs.parse_bundle(der_of("unrelated"))
    assert len(parsed) == 1


def test_parse_bundle_skips_unparseable_blocks() -> None:
    blob = (
        read_fixture_cert("weak-intermediate")
        + (FIXTURE_CERTS / "not-a-cert.pem").read_text(encoding="utf-8")
    ).encode()
    assert len(certs.parse_bundle(blob)) == 1


def test_parse_bundle_file_tolerates_missing_file(tmp_path) -> None:
    assert certs.parse_bundle_file(tmp_path / "absent.pem") == []


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x30",
        b"\x30\x82\xff\xff",  # length beyond the buffer
        b"\x02\x01\x00",  # an INTEGER, not a certificate
        b"\x30\x80\x00\x00",  # indefinite length is not DER
    ],
)
def test_malformed_der_is_rejected(blob: bytes) -> None:
    with pytest.raises(certs.CertificateParseError):
        certs.parse_certificate(blob)


def test_truncated_certificate_is_rejected() -> None:
    der = der_of("weak-intermediate")
    with pytest.raises(certs.CertificateParseError):
        certs.parse_certificate(der[: len(der) // 2])


def test_spki_index_groups_by_key() -> None:
    parsed = certs.parse_bundle(
        (read_fixture_cert("weak-intermediate") + read_fixture_cert("weak-intermediate")).encode()
    )
    index = certs.spki_index(parsed)
    assert len(index) == 1
    assert len(next(iter(index.values()))) == 2
