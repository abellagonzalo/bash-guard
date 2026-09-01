#!/usr/bin/env python3
"""Unit tests for guard/classifiers/bash.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_bash.py     # -> prints a summary, exits 1 on any failure
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import bash  # noqa: E402

# `bash <path>` only recurses into scripts under a trusted root (real
# `~/.claude`); point it at a throwaway temp dir for the duration of this
# test run so these cases never touch the real one.
_BASH_SCRIPT_ROOT = tempfile.mkdtemp()
bash._TRUSTED_SCRIPT_ROOTS = (_BASH_SCRIPT_ROOT,)

_BASH_READONLY_SCRIPT = os.path.join(_BASH_SCRIPT_ROOT, "readonly.sh")
with open(_BASH_READONLY_SCRIPT, "w") as _f:
    _f.write("#!/usr/bin/env bash\necho hi\n")

_BASH_MUTATING_SCRIPT = os.path.join(_BASH_SCRIPT_ROOT, "mutating.sh")
with open(_BASH_MUTATING_SCRIPT, "w") as _f:
    _f.write("#!/usr/bin/env bash\nrm -rf /\n")

# (label, tokens, expected_ok) -- bash -c recurses the inline script through
# the same classify pipeline (issue #13, phase 1); bash <path> recurses a
# script file read off disk, only when it resolves under a trusted root
# (issue #26, phase 2).
CASES = [
    ("bash -c read-only script", ["bash", "-c", "echo hi"], True),
    ("bash -c mutating script", ["bash", "-c", "rm -rf /"], False),
    ("bash -c with positional args stays read-only",
     ["bash", "-c", "echo $1", "ignored"], True),
    ("bash -c wrapping unknown command",
     ["bash", "-c", "notarealcmd"], False),
    ("bash <path> outside any trusted root defers",
     ["bash", "/some/script.sh"], False),
    ("bash <path> trusted root, read-only script",
     ["bash", _BASH_READONLY_SCRIPT], True),
    ("bash <path> trusted root, with positional args stays read-only",
     ["bash", _BASH_READONLY_SCRIPT, "arg1"], True),
    ("bash <path> trusted root, mutating script",
     ["bash", _BASH_MUTATING_SCRIPT], False),
    ("bash <path> existing file outside trusted root defers",
     ["bash", "/etc/hostname"], False),
    ("bash <path> nonexistent file under trusted root defers",
     ["bash", os.path.join(_BASH_SCRIPT_ROOT, "missing.sh")], False),
    ("bash <path> relative path defers",
     ["bash", "relative/script.sh"], False),
    ("bash bare defers", ["bash"], False),
    ("bash -c with extra leading flag defers (narrow shape)",
     ["bash", "-x", "-c", "echo hi"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = bash.classify(tokens)
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
