#!/usr/bin/env python3
"""Run emudhra-trust-audit straight from a checkout, with no installation step.

    python3 bin/emudhra-trust-audit.py endpoint
    py -3 bin\\emudhra-trust-audit.py project .

Only the Python standard library is used, so this works on macOS, Linux and
Windows with any Python 3.9 or newer.
"""

from __future__ import annotations

import os
import sys

sys.dont_write_bytecode = True

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

if sys.version_info < (3, 9):  # pragma: no cover
    sys.stderr.write(
        "emudhra-trust-audit needs Python 3.9 or newer; found %s\n" % sys.version.split()[0]
    )
    raise SystemExit(3)

from ca_trust_audit.cli import main  # noqa: E402  (path set up above)

if __name__ == "__main__":
    raise SystemExit(main())
