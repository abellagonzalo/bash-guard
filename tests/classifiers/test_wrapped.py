#!/usr/bin/env python3
"""Unit tests for guard/classifiers/wrapped.py.

Direct unit tests for the shared ``classify_wrapped()`` helper, which
find.py's -exec payload and xargs.py both delegate to (issue #18).
Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_wrapped.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers.wrapped import classify_wrapped  # noqa: E402

# (label, payload, context, expected_ok)
CASES = [
    ("empty payload", [], "find -exec", False),
    ("no wrapped command", None, "xargs", False),
    ("unknown wrapped command", ["notarealcmd"], "xargs", False),
    ("wrapped command not append-safe", ["curl", "https://x"], "xargs", False),
    ("wrapped command append-safe allows", ["cat", "x"], "find -exec", True),
    ("wrapped command append-safe denies", ["sed", "-i", "s/a/b/"], "xargs", False),
]


def main() -> int:
    failures = []
    for label, payload, context, expected in CASES:
        ok, _reason = classify_wrapped(payload, context=context)
        status = "ok" if ok == expected else "FAIL"
        if ok != expected:
            failures.append((label, payload, ok, expected))
        print(f"[{status}] {label}: got ok={ok}, want {expected}")

    print()
    if failures:
        print(f"{len(failures)}/{len(CASES)} FAILED:")
        for label, payload, got, want in failures:
            print(f"  {label}: got {got!r}, want {want!r} (payload={payload})")
        return 1
    print(f"All {len(CASES)} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
