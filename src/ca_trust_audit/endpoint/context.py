"""Execution context for the endpoint audit.

Every filesystem read goes through :meth:`EndpointContext.path`, so tests can
point the whole audit at a fixture tree instead of ``/``. Every process
execution goes through the injected :class:`~ca_trust_audit.util.CommandRunner`,
so platform-specific logic is testable from any CI runner.
"""

from __future__ import annotations

import dataclasses
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ..datafiles import DataBundle
from ..redact import Redactor
from ..util import CommandRunner


@dataclasses.dataclass
class EndpointContext:
    data: DataBundle
    system: str = dataclasses.field(default_factory=lambda: platform.system().lower())
    env: Mapping[str, str] = dataclasses.field(default_factory=lambda: dict(os.environ))
    runner: CommandRunner = dataclasses.field(default_factory=CommandRunner)
    fs_root: Optional[Path] = None
    redactor: Optional[Redactor] = None
    offline: bool = True
    network_host: str = ""
    extra_bundles: List[Path] = dataclasses.field(default_factory=list)
    include_user_stores: bool = True
    notes: List[str] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        if self.redactor is None:
            self.redactor = Redactor.from_env(self.env, windows=self.is_windows)

    @property
    def is_windows(self) -> bool:
        return self.system.startswith("win")

    @property
    def is_darwin(self) -> bool:
        return self.system == "darwin"

    @property
    def is_linux(self) -> bool:
        return self.system == "linux"

    def path(self, absolute: str) -> Path:
        """Resolve an absolute system path, honouring the test filesystem root."""
        if self.fs_root is None:
            return Path(absolute).expanduser()
        text = str(absolute)
        drive, rest = os.path.splitdrive(text)
        del drive
        return Path(self.fs_root) / rest.lstrip("/\\")

    def home(self) -> Optional[Path]:
        home = self.env.get("HOME") or self.env.get("USERPROFILE")
        return self.path(home) if home else None

    def show(self, value: object) -> str:
        assert self.redactor is not None
        return self.redactor.path(value)

    def describe(self) -> Dict[str, Any]:
        return {
            "system": self.system,
            "offline": self.offline,
            "commands": "enabled" if self.runner.enabled else "disabled",
            "fs_root": "/" if self.fs_root is None else str(self.fs_root),
        }
