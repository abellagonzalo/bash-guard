#!/usr/bin/env python3
"""Unit tests for guard/classifiers/tmpwrite.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_tmpwrite.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import tmpwrite  # noqa: E402

# (label, tokens, expected_ok) -- writes confined to a temp dir.
CASES = [
    ("touch tmp", ["touch", "/tmp/x"], True),
    ("touch etc", ["touch", "/etc/x"], False),
    ("touch mixed", ["touch", "/tmp/a", "/etc/b"], False),
    ("mkdir -p tmp", ["mkdir", "-p", "/tmp/a/b"], True),
    ("mkdir -m arg", ["mkdir", "-m", "755", "/tmp/d"], False),  # mode arg not a temp path
    ("touch -- tmp", ["touch", "--", "/tmp/x"], True),
    ("tee tmp", ["tee", "-a", "/tmp/log"], True),
    ("rm -rf tmp", ["rm", "-rf", "/tmp/x"], True),
    ("rm etc", ["rm", "/etc/x"], False),
    ("touch no operand", ["touch"], False),
    ("tmp traversal", ["touch", "/tmp/../etc/passwd"], False),
    ("tmp prefix trap", ["touch", "/tmpfoo"], False),
    ("tmpdir var", ["touch", "$TMPDIR/x"], True),
    ("private tmp", ["touch", "/private/tmp/x"], True),
    ("mv all tmp", ["mv", "/tmp/a", "/tmp/b"], True),
    ("mv both tmp flag", ["mv", "-f", "/tmp/a", "/tmp/b"], True),
    ("mv dest etc", ["mv", "/tmp/a", "/etc/b"], False),
    ("mv src etc", ["mv", "/etc/a", "/tmp/b"], False),  # mv removes source
    ("mv target-dir long", ["mv", "--target-directory=/etc", "/tmp/x"], False),
    ("mv target-dir attached", ["mv", "-t/root/.ssh", "/tmp/x"], False),
    ("mv target-dir sep", ["mv", "-t", "/etc", "/tmp/x"], False),
    # cp — source unrestricted, dest must be temp.
    ("cp src outside", ["cp", "/etc/hosts", "/tmp/h"], True),
    ("cp -r src outside", ["cp", "-r", "src", "/tmp/d"], True),
    ("cp dest outside", ["cp", "/tmp/a", "/etc/b"], False),
    ("cp target-dir flag", ["cp", "-t", "/etc", "src", "/tmp/x"], False),
    ("cp long flag", ["cp", "--target-directory=/etc", "src"], False),
    ("cp one operand", ["cp", "/tmp/x"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = tmpwrite.classify(tokens)
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
