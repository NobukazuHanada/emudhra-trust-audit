"""Run the scanner from a source checkout or a standalone skill bundle."""

import runpy
import sys
from pathlib import Path

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
bundled = here / "scripts" / "bin" / "emudhra-trust-audit.py"
entry = bundled if bundled.is_file() else here.parents[1] / "bin" / "emudhra-trust-audit.py"
runpy.run_path(str(entry), run_name="__main__")
