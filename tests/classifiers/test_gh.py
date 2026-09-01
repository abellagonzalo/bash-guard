#!/usr/bin/env python3
"""Unit tests for guard/classifiers/gh.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_gh.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import gh  # noqa: E402

# (label, tokens, expected_ok) -- read subcommands + GET-only api.
CASES = [
    ("gh pr view", ["gh", "pr", "view", "123"], True),
    ("gh pr list", ["gh", "pr", "list"], True),
    ("gh repo flag", ["gh", "-R", "o/r", "pr", "list"], True),
    ("gh pr create", ["gh", "pr", "create"], False),
    ("gh api get", ["gh", "api", "repos/foo"], True),
    ("gh api POST", ["gh", "api", "-X", "POST", "repos/foo"], False),
    ("gh api field", ["gh", "api", "repos/foo", "-f", "name=x"], False),
    ("gh unknown", ["gh", "secret", "set", "X"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = gh.classify(tokens)
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
