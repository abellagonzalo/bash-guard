#!/usr/bin/env python3
"""Unit tests for guard/classifiers/gradlew_mvnw.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_gradlew_mvnw.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import gradlew_mvnw  # noqa: E402

# (label, tokens, expected_ok) -- safe goals/flags vs. everything else.
CASES = [
    ("gradlew compileKotlin", ["./gradlew", "compileKotlin"], True),
    ("gradlew multiple safe goals",
     ["./gradlew", "compileKotlin", "compileTestKotlin", "-q"], True),
    ("gradlew test with --tests",
     ["./gradlew", "test", "--tests", "*FooTest*"], True),
    ("gradlew test with --tests=",
     ["./gradlew", "test", "--tests=*FooTest*"], True),
    ("mvnw dependency:tree with -pl and -D",
     ["./mvnw", "dependency:tree", "-pl", "booking",
      "-Dincludes=com.traderepublic.banking:banking-common"], True),
    ("mvnw spotless:apply not in safe set (issue #15 explicitly excludes *:apply)",
     ["./mvnw", "spotless:apply", "-pl", "booking", "-q"], False),
    ("gradlew unsafe goal", ["./gradlew", "publish"], False),
    ("mvnw deploy", ["./mvnw", "deploy"], False),
    ("gradlew bare (runs default task)", ["./gradlew"], False),
    ("gradlew flags only, no goal", ["./gradlew", "-q"], False),
    ("gradlew unrecognized flag", ["./gradlew", "compileKotlin", "--offline"], False),
    ("mvnw unrecognized flag", ["./mvnw", "dependency:tree", "-o"], False),
    ("mvnw -pl with no value swallows next token as value, not a goal",
     ["./mvnw", "dependency:tree", "-pl", "publish"], True),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = gradlew_mvnw.classify(tokens)
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
