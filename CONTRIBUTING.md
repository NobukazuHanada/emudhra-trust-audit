# Contributing

Use Python 3.9+; runtime code uses the standard library. Development tools are
installed explicitly in a virtual environment (this setup is not an audit):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install pytest ruff build
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m build
```

On Windows use `py -3 -m venv .venv` and `.venv\Scripts\python`.
Run `python -B bin/emudhra-trust-audit.py data --verify` and build the standalone
skills with `python scripts/build_skills.py <new-empty-directory>`.
CI runs tests, lint, formatting, data verification, skill builds and wheel smoke
checks on Linux, macOS and Windows with Python 3.9, 3.12 and 3.14.
Mocked OS responses do not replace testing a real patched and unpatched system.

Keep indicators and matching rules in `data/`, with sources, date and version.
Verify advisories against primary vendor/CA-program sources. Do not silently
extend a distribution's fixed version to a different distribution or branch.
After a reviewed data edit, run
`python -B bin/emudhra-trust-audit.py data --write-checksums` and review the resulting
digests. Never add runtime downloads of indicator data or remote fix scripts.
Checksums provide integrity, not authenticity; changes still need review.

Add regression tests for behavior, including malformed inputs, incomplete
coverage, no-network/no-write defaults, privacy and confidence. Use synthetic
certificates with no private keys in the repository. Do not add third-party PEMs,
scripts or archives without documenting redistribution permission and attribution.
Each finding ID must have an explanation in `explanations.py`.

The existing Python 3.9 typing and percent-formatting style is accepted by lint;
Ruff formats layout. Long explanatory strings are exempt from E501. Correctness,
unused imports and other configured rules still run.

Contributions are provided under Apache-2.0. Preserve NOTICE and third-party
attribution. Before publication set the actual repository URL, enable private
vulnerability reporting, and verify all three CI platforms. Publishing and pushing
are separate human actions; build/test commands never publish anything.
