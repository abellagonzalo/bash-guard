#!/usr/bin/env python3
"""Registry sanity tests for guard/registry.py.

Direct unit tests checking that representative command names resolve to the
right classifier module in ``guard.registry.CLASSIFIERS``. Cross-cutting
(spans most classifier modules), so it lives at the top level alongside
guard/registry.py rather than under tests/classifiers/. Stdlib-only, like
the sibling suites.

    python3 tests/test_registry.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from guard.classifiers import (  # noqa: E402
    awk, bash, command, curl, date, docker, env, find, gh, git,
    gradlew_mvnw, kubectl, psql, readonly, sed, sort, tmpwrite, xargs, yq,
)
from guard.registry import CLASSIFIERS  # noqa: E402

# Registry sanity: representative names resolve to the right module.
EXPECTED_REGISTRY = {
    "cat": readonly.classify, "grep": readonly.classify,
    "cd": readonly.classify,
    "find": find.classify, "sed": sed.classify, "awk": awk.classify,
    "gh": gh.classify, "git": git.classify, "env": env.classify,
    "docker": docker.classify, "kubectl": kubectl.classify,
    "command": command.classify, "curl": curl.classify,
    "date": date.classify, "psql": psql.classify,
    "sort": sort.classify, "yq": yq.classify,
    "touch": tmpwrite.classify, "cp": tmpwrite.classify,
    "xargs": xargs.classify, "bash": bash.classify,
    "./gradlew": gradlew_mvnw.classify, "./mvnw": gradlew_mvnw.classify,
}


def main() -> int:
    failures = []
    for name, fn in EXPECTED_REGISTRY.items():
        got = CLASSIFIERS.get(name)
        status = "ok" if got is fn else "FAIL"
        if got is not fn:
            failures.append((name, got, fn))
        print(f"[{status}] registry[{name}] resolves correctly")

    print()
    if failures:
        print(f"{len(failures)}/{len(EXPECTED_REGISTRY)} FAILED:")
        for name, got, want in failures:
            print(f"  registry[{name}]: got {got!r}, want {want!r}")
        return 1
    print(f"All {len(EXPECTED_REGISTRY)} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
