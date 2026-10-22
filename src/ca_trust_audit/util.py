"""Process execution and small helpers.

Each intended external probe is read-only and is spelled out as a fixed
argument vector in the source - never assembled from scanned content, never run
through a shell. The program name is additionally checked against
:data:`ALLOWED_PROGRAMS`, to catch accidental use of mutating commands such as ``update-ca-certificates`` or ``certutil -delstore``.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
from typing import Dict, Mapping, Optional, Sequence

DEFAULT_TIMEOUT = 20
MAX_CAPTURE = 4_000_000

#: Basenames of the programs the audit is permitted to execute.
ALLOWED_PROGRAMS = frozenset(
    {
        # platform identification
        "uname",
        "sw_vers",
        "getconf",
        "systeminfo",
        "cmd",
        # trust stores
        "security",
        "certutil",
        "powershell",
        "pwsh",
        "trust",
        # package managers (query subcommands only)
        "dpkg-query",
        "rpm",
        "pacman",
        "apk",
        "brew",
        "zypper",
        # runtimes and clients
        "openssl",
        "curl",
        "curl-config",
        "git",
        "node",
        "npm",
        "python",
        "python3",
        "pip",
        "pip3",
        "uv",
        "java",
        "go",
        "cargo",
        "rustc",
        "perl",
        "ruby",
        "php",
        "dotnet",
        "keytool",
        "claude",
        "codex",
    }
)

#: Sub-arguments that must never appear, as a second line of defence.
FORBIDDEN_ARGUMENTS = frozenset(
    {
        "-delstore",
        "-addstore",
        "-delete",
        "delete-certificate",
        "add-trusted-cert",
        "remove-trusted-cert",
        "update-ca-certificates",
        "update-ca-trust",
        "--set",
        "install",
        "uninstall",
        "upgrade",
        "remove",
    }
)


@dataclasses.dataclass(frozen=True)
class CommandResult:
    argv: Sequence[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and self.returncode == 0

    @property
    def program(self) -> str:
        return os.path.basename(self.argv[0]) if self.argv else ""


class CommandRunner:
    """Runs reviewed probe arguments; this allow list is not a process sandbox."""

    def __init__(self, *, env: Optional[Mapping[str, str]] = None, enabled: bool = True) -> None:
        self.env: Dict[str, str] = dict(env if env is not None else os.environ)
        self.enabled = enabled

    def which(self, program: str) -> Optional[str]:
        return shutil.which(program, path=self.env.get("PATH"))

    def run(self, argv: Sequence[str], timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        argv = list(argv)
        if not argv:
            return CommandResult(argv=argv, error="empty argument vector")
        program = os.path.basename(argv[0]).lower()
        if program.endswith(".exe"):
            program = program[:-4]
        if program not in ALLOWED_PROGRAMS:
            return CommandResult(
                argv=argv, error="program %r is not on the read-only allow list" % program
            )
        for argument in argv[1:]:
            if argument.lower() in FORBIDDEN_ARGUMENTS:
                return CommandResult(argv=argv, error="argument %r is not permitted" % argument)
        if not self.enabled:
            return CommandResult(argv=argv, error="command execution disabled")
        if self.which(argv[0]) is None and not os.path.isabs(argv[0]):
            return CommandResult(argv=argv, error="%s not found on PATH" % argv[0])
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                timeout=timeout,
                env=self.env,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(argv=argv, error="%s not found" % argv[0])
        except PermissionError:
            return CommandResult(argv=argv, error="not permitted to execute %s" % argv[0])
        except subprocess.TimeoutExpired:
            return CommandResult(argv=argv, error="timed out after %ds" % timeout)
        except OSError as error:  # pragma: no cover - platform dependent
            return CommandResult(argv=argv, error=str(error))
        return CommandResult(
            argv=argv,
            returncode=completed.returncode,
            stdout=completed.stdout[:MAX_CAPTURE].decode("utf-8", "replace"),
            stderr=completed.stderr[:MAX_CAPTURE].decode("utf-8", "replace"),
        )


class DisabledRunner(CommandRunner):
    """Executes nothing; used by ``--no-commands``."""

    def __init__(self, *, env: Optional[Mapping[str, str]] = None) -> None:
        super().__init__(env=env, enabled=False)

    def which(self, program: str) -> Optional[str]:  # pragma: no cover - trivial
        return None


def first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def truncate(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def read_regular_file(path, limit=16 * 1024 * 1024, *, nofollow=False):
    """Bound reads and reject devices/FIFOs; endpoint store symlinks are allowed.

    O_NONBLOCK prevents a FIFO replacement from hanging before fstat. Project
    callers separately reject links and require containment in their root.
    """
    import stat

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if nofollow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise OSError("not a bounded regular file")
        blob = handle.read(limit + 1)
        if len(blob) > limit:
            raise OSError("file exceeds read limit")
        return blob
