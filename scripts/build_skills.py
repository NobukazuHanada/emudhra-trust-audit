"""Build two portable skills, each with its own offline scanner and data."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("endpoint-trust-audit", "project-trust-audit"):
        target = destination / name
        if target.exists():
            raise FileExistsError("destination exists; choose an empty build directory")
        shutil.copytree(ROOT / "skills" / name, target)
        runtime = target / "scripts"
        runtime.mkdir(exist_ok=True)
        shutil.copytree(
            ROOT / "src",
            runtime / "src",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
        shutil.copytree(ROOT / "data", runtime / "data")
        (runtime / "bin").mkdir()
        shutil.copy2(ROOT / "bin" / "ca-trust-audit.py", runtime / "bin" / "ca-trust-audit.py")
        for filename in ("LICENSE", "NOTICE"):
            shutil.copy2(ROOT / filename, target / filename)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    build(parser.parse_args().destination)
