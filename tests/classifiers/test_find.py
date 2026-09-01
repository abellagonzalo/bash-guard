#!/usr/bin/env python3
"""Unit tests for guard/classifiers/find.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_find.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import find  # noqa: E402

# (label, tokens, expected_ok) -- mutating/executing actions defer.
CASES = [
    ("find name", ["find", ".", "-name", "*.py"], True),
    ("find delete", ["find", ".", "-delete"], False),
    ("find exec", ["find", ".", "-exec", "rm", "{}", ";"], False),
    ("find fprint", ["find", ".", "-fprint", "out"], False),
    # Escaped `\(`/`\)` reach the classifier as literal `(`/`)` operands.
    ("find parens",
     ["find", ".", "(", "-name", "*.kt", "-o", "-name", "*.yml", ")"], True),
    ("find parens delete",
     ["find", ".", "(", "-name", "*.kt", ")", "-delete"], False),
    # -exec payload recurses through the same APPEND_SAFE gate as xargs.
    ("find exec grep semicolon",
     ["find", ".", "-name", "*.kt", "-exec", "grep", "-l", "Foo", "{}", ";"], True),
    ("find exec cat plus",
     ["find", ".", "-name", "*.kt", "-exec", "cat", "{}", "+"], True),
    ("find exec rm append-safety regression guard",
     ["find", ".", "-exec", "rm", "{}", ";"], False),
    ("find exec cp append-safety regression guard",
     ["find", ".", "-exec", "cp", "{}", "/tmp/dst", ";"], False),
    ("find exec sh -c unknown wrapped command",
     ["find", ".", "-exec", "sh", "-c", "cat $0", "{}", ";"], False),
    ("find exec no terminator",
     ["find", ".", "-exec", "cat", "{}"], False),
    ("find exec no wrapped command",
     ["find", ".", "-exec", ";"], False),
    ("find exec wraps sed -i still deferred",
     ["find", ".", "-exec", "sed", "-i", "s/a/b/", "{}", ";"], False),
    ("find multiple exec clauses, second unsafe",
     ["find", ".", "-name", "a", "-exec", "cat", "{}", ";",
      "-o", "-name", "b", "-exec", "rm", "{}", ";"], False),
    ("find execdir unchanged hard deny",
     ["find", ".", "-execdir", "cat", "{}", ";"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = find.classify(tokens)
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
