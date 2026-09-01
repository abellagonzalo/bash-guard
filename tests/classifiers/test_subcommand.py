#!/usr/bin/env python3
"""Unit tests for guard/classifiers/subcommand.py.

Direct unit tests for the shared ``find_subcommand()`` helper, which
git/docker/kubectl all delegate to (issue #17). Stdlib-only, like the
sibling suites.

    python3 tests/classifiers/test_subcommand.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers.subcommand import find_subcommand  # noqa: E402

# (label, tokens, value_flags, expected_result)
CASES = [
    ("no flags", ["git", "status"], frozenset(), ("status", [])),
    ("value flag skipped", ["kubectl", "-n", "ns", "get", "pods"],
     frozenset({"-n"}), ("get", ["pods"])),
    ("unrecognized flag fails safe", ["git", "--git-dir", "status"],
     frozenset(), (None, None)),
    ("value flag's own value never mistaken for subcommand",
     ["docker", "--context", "ps", "run"], frozenset({"--context"}),
     ("run", [])),
    ("bare command fails safe", ["git"], frozenset(), (None, None)),
    ("only flags, no bare word fails safe", ["kubectl", "-n", "ns"],
     frozenset({"-n"}), (None, None)),
]


def main() -> int:
    failures = []
    for label, tokens, value_flags, expected in CASES:
        got = find_subcommand(tokens, value_flags=value_flags)
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
