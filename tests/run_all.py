#!/usr/bin/env python3
"""Runs every test_*.py under tests/ and tests/classifiers/ as a subprocess.

    python3 tests/run_all.py     # -> prints a per-file summary, exits 1 on any failure
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def main() -> int:
    files = sorted(HERE.glob("test_*.py")) + sorted(HERE.glob("classifiers/test_*.py"))
    failures = []
    for f in files:
        result = subprocess.run([sys.executable, str(f)])
        status = "ok" if result.returncode == 0 else "FAIL"
        if result.returncode != 0:
            failures.append(f)
        print(f"[{status}] {f.relative_to(HERE.parent)}")

    print()
    if failures:
        print(f"{len(failures)}/{len(files)} FAILED:")
        for f in failures:
            print(f"  {f.relative_to(HERE.parent)}")
        return 1
    print(f"All {len(files)} suites passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
