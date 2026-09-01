#!/usr/bin/env python3
"""Unit tests for guard/classifiers/xargs.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_xargs.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import xargs  # noqa: E402

# (label, tokens, expected_ok) -- recurses into an append-safe wrapped
# command only.
CASES = [
    ("xargs grep", ["xargs", "grep", "-l", "Foo"], True),
    ("xargs wc", ["xargs", "wc", "-l"], True),
    ("xargs -0 -n opts then grep",
     ["xargs", "-0", "-n", "10", "grep", "-l", "y"], True),
    ("xargs -n attached", ["xargs", "-n5", "grep", "y"], True),
    ("xargs -- separator", ["xargs", "--", "grep", "-l", "y"], True),
    ("xargs wraps sed non-inplace", ["xargs", "sed", "-n", "1,5p"], True),
    ("xargs no wrapped command", ["xargs"], False),
    ("xargs only its own flags", ["xargs", "-0", "-n", "5"], False),
    ("xargs rm append-safety regression guard",
     ["xargs", "rm", "/tmp/safe"], False),
    ("xargs cp -t", ["xargs", "cp", "-t", "/tmp/dst"], False),
    ("xargs sh -c", ["xargs", "sh", "-c", "cat $0"], False),
    ("xargs unknown wrapped command", ["xargs", "notarealcmd"], False),
    # bash is a known command now (issue #13) but not append-safe, so
    # wrapping it via xargs must still defer, same as before registration.
    ("xargs wraps bash -c (not append-safe)",
     ["xargs", "bash", "-c", "echo hi"], False),
    ("xargs wraps sed -i still deferred",
     ["xargs", "sed", "-i", "s/a/b/"], False),
    ("xargs wraps sort -o deferred", ["xargs", "sort", "-o", "out"], False),
    ("xargs wraps curl (not append-safe)",
     ["xargs", "curl", "https://x"], False),
    ("xargs wraps env (not append-safe)", ["xargs", "env", "FOO=1"], False),
    ("xargs -I replace deny", ["xargs", "-I{}", "echo", "{}"], False),
    ("xargs -i bare replace deny", ["xargs", "-i", "echo", "{}"], False),
    ("xargs --replace deny", ["xargs", "--replace", "echo", "{}"], False),
    ("xargs -J BSD replace deny", ["xargs", "-J", "%", "echo", "%"], False),
    ("xargs unrecognized flag deny",
     ["xargs", "--totally-bogus", "grep", "y"], False),
    ("xargs nested xargs defers", ["xargs", "xargs", "grep", "y"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = xargs.classify(tokens)
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
