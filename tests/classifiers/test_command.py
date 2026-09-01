#!/usr/bin/env python3
"""Unit tests for guard/classifiers/command.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_command.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import command  # noqa: E402

# (label, tokens, expected_ok) -- lookup vs run.
CASES = [
    ("command -v", ["command", "-v", "ls"], True),
    ("command -V", ["command", "-V", "ls"], True),
    ("command -p -v", ["command", "-p", "-v", "ls"], True),
    ("command run", ["command", "rm", "x"], False),
    ("command run flag late", ["command", "bash", "-v", "-c", "x"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = command.classify(tokens)
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
