"""Read trusted certificates out of a JKS truststore.

A JDK ``cacerts`` file is an independent trust store: patching the operating
system does not touch it. The trusted-certificate entries of a JKS file are not
encrypted - the store password only protects the integrity digest and private
key entries - so they can be read without any password being supplied.

Private key entries are skipped by length; their bytes are never decoded,
decrypted or emitted.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Optional, Tuple

from .util import read_regular_file

MAGIC_JKS = 0xFEEDFEED
MAGIC_JCEKS = 0xCECECECE

TAG_PRIVATE_KEY = 1
TAG_TRUSTED_CERT = 2


class KeystoreError(ValueError):
    """The file is not a readable JKS/JCEKS keystore."""


def detect_format(blob: bytes) -> str:
    if len(blob) < 4:
        return "unknown"
    magic = struct.unpack(">I", blob[:4])[0]
    if magic == MAGIC_JKS:
        return "jks"
    if magic == MAGIC_JCEKS:
        return "jceks"
    if blob[:1] == b"\x30":
        return "pkcs12"
    return "unknown"


def _read_utf(blob: bytes, offset: int) -> Tuple[str, int]:
    if offset + 2 > len(blob):
        raise KeystoreError("truncated keystore: missing string length")
    (length,) = struct.unpack_from(">H", blob, offset)
    offset += 2
    if offset + length > len(blob):
        raise KeystoreError("truncated keystore: missing string body")
    text = blob[offset : offset + length].decode("utf-8", "replace")
    return text, offset + length


def trusted_certificates(blob: bytes) -> List[Tuple[str, bytes]]:
    """Return ``(alias, der)`` for every trusted certificate entry."""
    kind = detect_format(blob)
    if kind not in ("jks", "jceks"):
        raise KeystoreError("not a JKS/JCEKS keystore (detected %s)" % kind)
    if len(blob) < 12:
        raise KeystoreError("truncated keystore header")
    _magic, version, count = struct.unpack_from(">IiI", blob, 0)
    if version not in (1, 2):
        raise KeystoreError("unsupported keystore version %d" % version)
    offset = 12
    out: List[Tuple[str, bytes]] = []
    for _ in range(count):
        if offset + 4 > len(blob):
            raise KeystoreError("truncated keystore: missing entry tag")
        (tag,) = struct.unpack_from(">I", blob, offset)
        offset += 4
        alias, offset = _read_utf(blob, offset)
        offset += 8  # creation timestamp
        if tag == TAG_TRUSTED_CERT:
            der, offset = _read_certificate(blob, offset, version)
            out.append((alias, der))
        elif tag == TAG_PRIVATE_KEY:
            if offset + 4 > len(blob):
                raise KeystoreError("truncated keystore: missing key length")
            (key_length,) = struct.unpack_from(">I", blob, offset)
            offset += 4 + key_length  # protected key bytes are skipped, never read
            if offset + 4 > len(blob):
                raise KeystoreError("truncated keystore: missing chain length")
            (chain_length,) = struct.unpack_from(">I", blob, offset)
            offset += 4
            for _index in range(chain_length):
                _der, offset = _read_certificate(blob, offset, version)
        else:
            raise KeystoreError("unknown keystore entry tag %d" % tag)
    return out


def _read_certificate(blob: bytes, offset: int, version: int) -> Tuple[bytes, int]:
    if version == 2:
        _cert_type, offset = _read_utf(blob, offset)
    if offset + 4 > len(blob):
        raise KeystoreError("truncated keystore: missing certificate length")
    (length,) = struct.unpack_from(">I", blob, offset)
    offset += 4
    if offset + length > len(blob):
        raise KeystoreError("truncated keystore: missing certificate body")
    return blob[offset : offset + length], offset + length


def read_file(path: Path, *, max_bytes: int = 33_554_432) -> Optional[List[Tuple[str, bytes]]]:
    """Read a keystore file; ``None`` when it cannot be read or parsed."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        blob = read_regular_file(path)
    except OSError:
        return None
    try:
        return trusted_certificates(blob)
    except KeystoreError:
        return None
