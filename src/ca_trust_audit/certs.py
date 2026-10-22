"""Minimal, dependency-free X.509 reading.

Only what an audit needs is implemented: the SHA-256 of the certificate and the
SHA-256 of its ``SubjectPublicKeyInfo`` (the primary match key for this class of
incident), plus the subject common name for human-readable evidence.

No signature verification, no private key handling, no key material is ever
read, derived or written.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from .util import read_regular_file

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_OID = 0x06
TAG_CONTEXT_0 = 0xA0

_OID_COMMON_NAME = bytes([0x55, 0x04, 0x03])
_OID_ORGANIZATION = bytes([0x55, 0x04, 0x0A])

_PEM_BLOCK = re.compile(
    rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.+?)-----END (?:TRUSTED )?CERTIFICATE-----",
    re.DOTALL,
)

_TEXT_TAGS = {0x0C, 0x13, 0x16, 0x14, 0x15, 0x1A, 0x1B}
_BMP_TAG = 0x1E


class CertificateParseError(ValueError):
    """Raised when a byte string is not a parseable DER certificate."""


@dataclasses.dataclass(frozen=True)
class ParsedCertificate:
    sha256: str
    spki_sha256: str
    subject_cn: str = ""
    subject_o: str = ""
    source: str = ""
    index: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "sha256": self.sha256,
            "spki_sha256": self.spki_sha256,
            "subject_cn": self.subject_cn,
            "subject_o": self.subject_o,
            "source": self.source,
            "index": self.index,
        }


@dataclasses.dataclass(frozen=True)
class _Field:
    """One DER element, with offsets into the buffer it was read from."""

    tag: int
    start: int  # offset of the tag byte
    content: int  # offset of the first content byte
    length: int  # content length

    @property
    def end(self) -> int:
        return self.content + self.length

    def raw(self, data: bytes) -> bytes:
        """The complete tag+length+value encoding of this element."""
        return data[self.start : self.end]


def _read_tlv(data: bytes, offset: int) -> _Field:
    if offset >= len(data):
        raise CertificateParseError("truncated DER: no tag at offset %d" % offset)
    tag = data[offset]
    pos = offset + 1
    if pos >= len(data):
        raise CertificateParseError("truncated DER: no length byte")
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise CertificateParseError("indefinite length is not valid DER")
    else:
        count = first & 0x7F
        if count > 4 or pos + count > len(data):
            raise CertificateParseError("unsupported DER length encoding")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise CertificateParseError("truncated DER: declared length exceeds buffer")
    return _Field(tag=tag, start=offset, content=pos, length=length)


def _children(data: bytes, content_offset: int, content_end: int) -> Iterator[_Field]:
    pos = content_offset
    while pos < content_end:
        field = _read_tlv(data, pos)
        if field.end > content_end:
            raise CertificateParseError("child element overruns its parent")
        yield field
        pos = field.end


def _decode_directory_string(data: bytes, field: _Field) -> str:
    raw = data[field.content : field.end]
    if field.tag == _BMP_TAG:
        try:
            return raw.decode("utf-16-be").strip()
        except UnicodeDecodeError:
            return ""
    if field.tag in _TEXT_TAGS:
        return raw.decode("utf-8", "replace").strip()
    return ""


def _name_attribute(der: bytes, name: _Field, oid: bytes) -> str:
    for rdn in _children(der, name.content, name.end):
        if rdn.tag != TAG_SET:
            continue
        for atv in _children(der, rdn.content, rdn.end):
            if atv.tag != TAG_SEQUENCE:
                continue
            fields = list(_children(der, atv.content, atv.end))
            if len(fields) < 2:
                continue
            oid_field, value_field = fields[0], fields[1]
            if oid_field.tag != TAG_OID:
                continue
            if der[oid_field.content : oid_field.end] != oid:
                continue
            return _decode_directory_string(der, value_field)
    return ""


def _looks_like_spki(der: bytes, field: _Field) -> bool:
    children = list(_children(der, field.content, field.end))
    return (
        len(children) == 2 and children[0].tag == TAG_SEQUENCE and children[1].tag == TAG_BIT_STRING
    )


def parse_certificate(der: bytes, *, source: str = "", index: int = 0) -> ParsedCertificate:
    """Parse a DER certificate into the few fields an audit reports."""
    certificate = _read_tlv(der, 0)
    if certificate.tag != TAG_SEQUENCE:
        raise CertificateParseError("certificate is not a SEQUENCE")

    tbs = _read_tlv(der, certificate.content)
    if tbs.tag != TAG_SEQUENCE:
        raise CertificateParseError("tbsCertificate is not a SEQUENCE")
    if tbs.end > certificate.end:
        raise CertificateParseError("tbsCertificate overruns the certificate")

    fields = list(_children(der, tbs.content, tbs.end))
    if not fields:
        raise CertificateParseError("empty tbsCertificate")
    cursor = 1 if fields[0].tag == TAG_CONTEXT_0 else 0  # optional explicit version
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < cursor + 6:
        raise CertificateParseError("tbsCertificate has too few fields")
    if fields[cursor].tag != TAG_INTEGER:
        raise CertificateParseError("serialNumber is not an INTEGER")
    subject = fields[cursor + 4]
    spki = fields[cursor + 5]
    if spki.tag != TAG_SEQUENCE or not _looks_like_spki(der, spki):
        raise CertificateParseError("subjectPublicKeyInfo is not a well-formed SEQUENCE")

    return ParsedCertificate(
        sha256=hashlib.sha256(certificate.raw(der)).hexdigest(),
        spki_sha256=hashlib.sha256(spki.raw(der)).hexdigest(),
        subject_cn=_name_attribute(der, subject, _OID_COMMON_NAME),
        subject_o=_name_attribute(der, subject, _OID_ORGANIZATION),
        source=source,
        index=index,
    )


def iter_der_blocks(blob: bytes) -> Iterator[bytes]:
    """Yield DER certificates from a PEM bundle or a single DER file."""
    matches = _PEM_BLOCK.findall(blob)
    if matches:
        for body in matches:
            try:
                yield base64.b64decode(re.sub(rb"\s+", b"", body), validate=True)
            except (binascii.Error, ValueError):
                continue
        return
    if blob[:1] == b"\x30":
        yield blob


def parse_bundle(blob: bytes, *, source: str = "") -> List[ParsedCertificate]:
    """Parse every certificate in a PEM/DER blob, skipping unparseable ones."""
    out: List[ParsedCertificate] = []
    for index, der in enumerate(iter_der_blocks(blob)):
        try:
            out.append(parse_certificate(der, source=source, index=index))
        except CertificateParseError:
            continue
    return out


def parse_bundle_file(
    path: Path, *, source: Optional[str] = None, max_bytes: int = 33_554_432
) -> List[ParsedCertificate]:
    """Read and parse a bundle file. Returns an empty list if unreadable."""
    try:
        if path.stat().st_size > max_bytes:
            return []
        blob = read_regular_file(path, max_bytes)
    except OSError:
        return []
    return parse_bundle(blob, source=source if source is not None else str(path))


def spki_index(certificates: Iterable[ParsedCertificate]) -> Dict[str, List[ParsedCertificate]]:
    index: Dict[str, List[ParsedCertificate]] = {}
    for certificate in certificates:
        index.setdefault(certificate.spki_sha256.lower(), []).append(certificate)
    return index
