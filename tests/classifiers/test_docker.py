#!/usr/bin/env python3
"""Unit tests for guard/classifiers/docker.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_docker.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import docker  # noqa: E402

# (label, tokens, expected_ok) -- pure reads + conditional subcommands.
CASES = [
    ("docker ps", ["docker", "ps"], True),
    ("docker logs", ["docker", "logs", "x"], True),
    ("docker info", ["docker", "info"], True),
    ("docker inspect", ["docker", "inspect", "x"], True),
    ("docker --version", ["docker", "--version"], True),
    ("docker context ls", ["docker", "context", "ls"], True),
    ("docker context rm", ["docker", "context", "rm", "x"], False),
    ("docker compose ps", ["docker", "compose", "ps"], True),
    ("docker compose up", ["docker", "compose", "up", "-d"], False),
    ("docker compose down", ["docker", "compose", "down"], False),
    ("docker compose bare", ["docker", "compose"], False),
    ("docker exec", ["docker", "exec", "-it", "x", "sh"], False),
    ("docker bare", ["docker"], False),
    # issue #17: --context takes a separate value; misreading it as boolean
    # let "ps" be mistaken for the subcommand while the real "run" was hidden.
    ("docker --context value misread as subcommand",
     ["docker", "--context", "ps", "run", "alpine", "bash"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = docker.classify(tokens)
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
