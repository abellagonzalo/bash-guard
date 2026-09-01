#!/usr/bin/env python3
"""Unit tests for guard/classifiers/curl.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_curl.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import curl  # noqa: E402

# (label, tokens, expected_ok) -- GET/HEAD reads + temp-dir output;
# bodies/uploads/non-temp writes defer.
CASES = [
    ("curl bare get", ["curl", "https://x"], True),
    ("curl -fsSL get", ["curl", "-fsSL", "https://x"], True),
    ("curl -X GET", ["curl", "-X", "GET", "https://x"], True),
    ("curl -XGET", ["curl", "-XGET", "https://x"], True),
    ("curl head", ["curl", "-I", "https://x"], True),
    ("curl header", ["curl", "-H", "X-Foo: bar", "https://x"], True),
    ("curl -o tmp", ["curl", "-o", "/tmp/x", "https://x"], True),
    ("curl -o attached tmp", ["curl", "-o/tmp/x", "https://x"], True),
    ("curl --output=tmp", ["curl", "--output=/tmp/x", "https://x"], True),
    ("curl --output-dir tmp", ["curl", "--output-dir", "/tmp", "https://x"], True),
    ("curl -o etc", ["curl", "-o", "/etc/x", "https://x"], False),
    ("curl -X POST", ["curl", "-X", "POST", "https://x"], False),
    ("curl -XPOST", ["curl", "-XPOST", "https://x"], False),
    ("curl --request=PUT", ["curl", "--request=PUT", "https://x"], False),
    ("curl data", ["curl", "-d", "a=b", "https://x"], False),
    ("curl --data=x", ["curl", "--data=a=b", "https://x"], False),
    ("curl form", ["curl", "-F", "f=@x", "https://x"], False),
    ("curl upload", ["curl", "-T", "f", "https://x"], False),
    ("curl remote-name", ["curl", "-O", "https://x"], False),
    ("curl bundled remote-name", ["curl", "-sO", "https://x"], False),
    ("curl config", ["curl", "-K", "cfg"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = curl.classify(tokens)
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
