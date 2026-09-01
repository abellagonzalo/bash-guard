#!/usr/bin/env python3
"""Unit tests for guard/classifiers/awk.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_awk.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import awk  # noqa: E402

# (label, tokens, expected_ok) -- shell-out / file output / pipe-to-command defer.
CASES = [
    ("awk print", ["awk", "{print $1}", "f"], True),
    ("awk logical or", ["awk", "$1>0 || $2>0", "f"], True),
    ("awk system", ["awk", '{system("rm x")}', "f"], False),
    ("awk system space", ["awk", '{system ("id")}', "f"], False),
    ("awk getline", ["awk", "{getline}", "f"], False),
    ("awk file-out", ["awk", "{print > \"x\"}", "f"], False),
    ("awk pipe shell", ["awk", 'BEGIN{print "id" | "sh"}'], False),
    ("awk coproc pipe", ["awk", 'BEGIN{print "id" |& "sh"}'], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = awk.classify(tokens)
        status = "ok" if ok == expected else "FAIL"
        if ok != expected:
            failures.append((label, tokens, ok, expected))
        print(f"[{status}] {label}: got ok={ok}, want {expected}")

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
