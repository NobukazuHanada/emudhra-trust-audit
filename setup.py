"""Include the reviewed data snapshot in wheels without duplicating source data."""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        super().run()
        shutil.copytree(
            Path(__file__).parent / "data",
            Path(self.build_lib) / "ca_trust_audit" / "data",
            dirs_exist_ok=True,
        )


setup(cmdclass={"build_py": BuildPy})
