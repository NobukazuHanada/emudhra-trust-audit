"""Project walking: one bounded, read-only pass over the repository."""

from __future__ import annotations

import dataclasses
import fnmatch
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from ..datafiles import DataBundle
from ..redact import Redactor


@dataclasses.dataclass
class ProjectFile:
    relative: str
    size: int
    too_large: bool = False


IGNORE_FILE = ".ca-trust-audit-ignore"


@dataclasses.dataclass
class ProjectContext:
    root: Path
    data: DataBundle
    env: Mapping[str, str] = dataclasses.field(default_factory=dict)
    include_containers: bool = True
    redactor: Optional[Redactor] = None
    files: List[ProjectFile] = dataclasses.field(default_factory=list)
    problems: List[str] = dataclasses.field(default_factory=list)
    truncated: bool = False
    ignored: List[str] = dataclasses.field(default_factory=list)
    notes: List[str] = dataclasses.field(default_factory=list)
    _cache: Dict[str, Optional[str]] = dataclasses.field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()
        if self.redactor is None:
            self.redactor = Redactor.from_env(self.env, root=self.root, windows=os.name == "nt")

    @property
    def ignore_patterns(self) -> List[str]:
        """Globs from ``.ca-trust-audit-ignore``; every skip is reported, never silent."""
        text = self.read_text(IGNORE_FILE)
        if text is None:
            return []
        patterns: List[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
        return patterns

    def _is_ignored(self, relative: str, patterns: Sequence[str]) -> bool:
        for pattern in patterns:
            if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(
                relative, pattern.rstrip("/") + "/*"
            ):
                return True
            if pattern.endswith("/**") and relative.startswith(pattern[:-3].rstrip("/") + "/"):
                return True
        return False

    def is_self_data(self, relative: str) -> bool:
        """True for a copy of this tool's own indicator data, ruleset or policy.

        Such a file lists the very patterns the scanner looks for, so matching it
        against itself produces noise rather than findings. Identified by the ids
        of the loaded data set, so a fork's renamed copy is recognised too.
        """
        if not relative.lower().endswith(".json"):
            return False
        text = self.read_text(relative)
        if text is None:
            return False
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return False
        if not isinstance(payload, dict):
            return False
        return any(
            payload == own
            for own in (
                self.data.insecure_rules,
                self.data.inventory,
                self.data.policy,
                self.data.incident,
            )
        )

    @property
    def scan_config(self) -> Dict[str, object]:
        return dict(self.data.insecure_rules.get("scan", {}))

    @property
    def exclude_dirs(self) -> Sequence[str]:
        return list(self.scan_config.get("exclude_dirs", []))  # type: ignore[arg-type]

    @property
    def max_files(self) -> int:
        return int(self.scan_config.get("max_files", 20000))  # type: ignore[arg-type]

    @property
    def max_file_bytes(self) -> int:
        return int(self.scan_config.get("max_file_bytes", 1_048_576))  # type: ignore[arg-type]

    def walk(self) -> List[ProjectFile]:
        """Collect repository files once, pruning excluded directories."""
        if self.files:
            return self.files
        excluded = set(self.exclude_dirs)
        patterns = self.ignore_patterns
        collected: List[ProjectFile] = []
        for dirpath, dirnames, filenames in os.walk(
            self.root,
            followlinks=False,
            onerror=lambda error: self.problems.append("directory unreadable"),
        ):
            kept = []
            for name in sorted(dirnames):
                child = Path(dirpath) / name
                if child.is_symlink() or child.resolve().parent != Path(dirpath).resolve():
                    self.problems.append("linked directory skipped")
                elif name not in excluded:
                    kept.append(name)
            dirnames[:] = kept
            for filename in sorted(filenames):
                absolute = Path(dirpath) / filename
                if absolute.is_symlink():
                    self.problems.append("symlink skipped")
                    continue
                try:
                    info = absolute.stat()
                    if not stat.S_ISREG(info.st_mode):
                        self.problems.append("special file skipped")
                        continue
                    size = info.st_size
                    if size > self.max_file_bytes:
                        self.problems.append("oversized file skipped")
                except OSError:
                    self.problems.append("file unreadable")
                    continue
                relative = PurePosixPath(absolute.relative_to(self.root).as_posix())
                if patterns and self._is_ignored(str(relative), patterns):
                    self.ignored.append(str(relative))
                    continue
                collected.append(
                    ProjectFile(
                        relative=str(relative),
                        size=size,
                        too_large=size > self.max_file_bytes,
                    )
                )
                if len(collected) >= self.max_files:
                    self.truncated = True
                    self.files = collected
                    return self.files
        self.files = collected
        return self.files

    def absolute(self, relative: str) -> Path:
        return self.root / relative

    def read_text(self, relative: str) -> Optional[str]:
        if relative in self._cache:
            return self._cache[relative]
        blob = self.read_bytes(relative)
        text = blob.decode("utf-8", "replace") if blob is not None else None
        self._cache[relative] = text
        return text

    def read_bytes(self, relative: str) -> Optional[bytes]:
        path = self.absolute(relative)
        try:
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("non-relative path")
            resolved = path.resolve()
            resolved.relative_to(self.root)
            # Reject symlinks and Windows junctions in every path component.
            current = path
            while current != self.root:
                if current.is_symlink() or current.resolve() != current.absolute():
                    raise ValueError("linked path")
                current = current.parent
            from ..util import read_regular_file

            return read_regular_file(path, self.max_file_bytes, nofollow=True)
        except (OSError, ValueError):
            if path.exists() or relative != IGNORE_FILE:
                self.problems.append("file unavailable, linked, outside root or oversized")
            return None

    def show(self, relative: str) -> str:
        assert self.redactor is not None
        return self.redactor.path(self.absolute(relative))

    def match(self, patterns: Iterable[str]) -> List[ProjectFile]:
        """Files matching any glob; a pattern without '/' matches the basename."""
        results: List[ProjectFile] = []
        patterns = list(patterns)
        for entry in self.walk():
            basename = entry.relative.rsplit("/", 1)[-1]
            for pattern in patterns:
                if "/" in pattern:
                    if fnmatch.fnmatch(entry.relative, pattern) or fnmatch.fnmatch(
                        entry.relative, "*/" + pattern
                    ):
                        results.append(entry)
                        break
                elif fnmatch.fnmatch(basename, pattern):
                    results.append(entry)
                    break
        return results

    def is_text_candidate(self, entry: ProjectFile) -> bool:
        suffixes = [str(value) for value in self.scan_config.get("text_suffixes", [])]  # type: ignore[arg-type]
        filenames = [str(value) for value in self.scan_config.get("text_filenames", [])]  # type: ignore[arg-type]
        basename = entry.relative.rsplit("/", 1)[-1]
        if basename in filenames:
            return True
        suffix = ("." + basename.rsplit(".", 1)[-1]).lower() if "." in basename else ""
        return suffix in [value.lower() for value in suffixes]
