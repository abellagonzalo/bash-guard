#!/usr/bin/env python3
"""Unit tests for guard/classifiers/flags.py.

Direct unit tests for the shared ``flag_value()`` helper, which curl.py and
psql.py both delegate to (issue #20). Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_flags.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers.flags import flag_value  # noqa: E402

# (label, tokens, i, attached, expected)
CASES = [
    ("inline value", ["-XGET"], 0, "GET", ("GET", 1)),
    ("separated value, present", ["-X", "GET"], 0, None, ("GET", 2)),
    ("separated value, missing at end", ["-X"], 0, None, (None, 1)),
    ("explicit empty inline value not treated as missing",
     ["--output="], 0, "", ("", 1)),
    ("inline value mid-token-stream advances past this token only",
     ["-cselect 1", "-x"], 0, "select 1", ("select 1", 1)),
]


def main() -> int:
    failures = []
    for label, tokens, i, attached, expected in CASES:
        got = flag_value(tokens, i, attached)
        status = "ok" if got == expected else "FAIL"
        if got != expected:
            failures.append((label, tokens, got, expected))
        print(f"[{status}] {label}: got {got}, want {expected}")

    print()
    if failures:
        print(f"{len(failures)}/{len(CASES)} FAILED:")
        for label, tokens, got, want in failures:
            print(f"  {label}: got {got!r}, want {want!r} (tokens={tokens})")
        return 1
    print(f"All {len(CASES)} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
