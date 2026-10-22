"""Path and value redaction.

Rules applied to everything that reaches the report:

* a path inside the audited project is emitted relative to the project root;
* a path inside the user's home directory is emitted with ``~`` (or
  ``%USERPROFILE%`` on Windows) in place of the home directory;
* the account name is replaced wherever it still appears;
* values of environment variables are never emitted - only the variable name
  and where it was set.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePath
from typing import Mapping, Optional

SECRET_NAME_PATTERN = re.compile(
    r"(pass|pwd|secret|token|key|credential|auth|cookie|session|salt|signature)",
    re.IGNORECASE,
)


class Redactor:
    """Rewrites host-specific paths into a form that is safe to publish."""

    def __init__(
        self,
        *,
        home: Optional[str] = None,
        user: Optional[str] = None,
        root: Optional[Path] = None,
        windows: bool = False,
    ) -> None:
        self.home = home
        self.user = user
        self.root = root
        self.windows = windows
        self._home_token = "%USERPROFILE%" if windows else "~"

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        *,
        root: Optional[Path] = None,
        windows: bool = False,
    ) -> Redactor:
        home = env.get("HOME") or env.get("USERPROFILE")
        user = env.get("USER") or env.get("USERNAME") or env.get("LOGNAME")
        return cls(home=home, user=user, root=root, windows=windows)

    def path(self, value: object) -> str:
        if value is None:
            return ""
        text = str(value)
        if not text:
            return ""
        if self.root is not None:
            try:
                relative = PurePath(os.path.abspath(text)).relative_to(
                    PurePath(os.path.abspath(str(self.root)))
                )
                return relative.as_posix() or "."
            except ValueError:
                pass
        if self.home:
            home = self.home.rstrip("/\\")
            if home and (
                text == home or text.startswith(home + os.sep) or text.startswith(home + "/")
            ):
                remainder = text[len(home) :].lstrip("/\\")
                text = self._home_token + ("/" + remainder if remainder else "")
        return self.text(text)

    def text(self, value: str) -> str:
        if self.user and len(self.user) >= 3:
            value = re.sub(re.escape(self.user), "<user>", value)
        return value

    def relative_to_root(self, value: object) -> str:
        """Project-relative path; falls back to the home-redacted form."""
        return self.path(value)


def is_secretish(name: str) -> bool:
    """True when an identifier looks like it names a credential."""
    return bool(SECRET_NAME_PATTERN.search(name))


def sanitize_report(report, redactor):
    """Scrub structured report strings in place before text/JSON/SARIF rendering."""
    import dataclasses

    secrets = [
        value for name, value in os.environ.items() if is_secretish(name) and len(value) >= 4
    ]

    def clean(value):
        if isinstance(value, str):
            if redactor.home:
                value = value.replace(redactor.home, redactor._home_token)
            value = redactor.text(value)
            for secret in secrets:
                value = value.replace(secret, "<redacted>")
            value = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1<redacted>@", value)
            value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "<email>", value)
            return value
        if dataclasses.is_dataclass(value):
            for field in dataclasses.fields(value):
                object.__setattr__(value, field.name, clean(getattr(value, field.name)))
        elif isinstance(value, list):
            return [clean(item) for item in value]
        elif isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()}
        return value

    clean(report)
