#!/usr/bin/env python3
"""Unit tests for guard/classifiers/python.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_python.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import python  # noqa: E402

_READ_AND_PRINT = (
    "import json\n"
    "with open('/path/to/file.txt') as f:\n"
    "    data = json.load(f)\n"
    "print(data['messages'][:1500])\n"
)

# (label, tokens, expected_ok)
CASES = [
    ("-c read-and-print sample from the issue",
     ["python3", "-c", _READ_AND_PRINT], True),
    ("-c bare print", ["python3", "-c", "print(1)"], True),
    ("-c with safe imports", ["python", "-c", "import re, math\nprint(re.match('a', 'a'))"], True),
    ("-c open() with explicit safe mode",
     ["python3", "-c", "open('f', 'r').read()"], True),
    ("-c open() with mode=r keyword",
     ["python3", "-c", "open('f', mode='r').read()"], True),
    ("-c trailing positional args stay opaque",
     ["python3", "-c", "print(1)", "ignored", "args"], True),

    ("-c open() write mode denies",
     ["python3", "-c", "open('f', 'w').write('x')"], False),
    ("-c open() append mode denies",
     ["python3", "-c", "open('f', 'a').write('x')"], False),
    ("-c open() non-literal mode denies",
     ["python3", "-c", "m = 'r'\nopen('f', m).read()"], False),
    ("-c import os denies",
     ["python3", "-c", "import os\nos.remove('/tmp/x')"], False),
    ("-c import subprocess denies",
     ["python3", "-c", "import subprocess\nsubprocess.run(['ls'])"], False),
    ("-c import pathlib denies",
     ["python3", "-c", "import pathlib\npathlib.Path('f').unlink()"], False),
    ("-c from-import outside allowlist denies",
     ["python3", "-c", "from os import remove\nremove('/tmp/x')"], False),
    ("-c reflection sandbox escape denies",
     ["python3", "-c", "().__class__.__bases__[0].__subclasses__()"], False),
    ("-c __globals__ escape denies",
     ["python3", "-c", "print.__globals__"], False),
    ("-c eval denies", ["python3", "-c", "eval('1')"], False),
    ("-c exec denies", ["python3", "-c", "exec('1')"], False),
    ("-c getattr-built dunder denies",
     ["python3", "-c", "getattr(().__class__, '__base' + '__')"], False),
    ("-c unsafe attr name on allowed module denies",
     ["python3", "-c", "import json\njson.write('x')"], False),
    ("-c syntax error denies",
     ["python3", "-c", "def :::"], False),

    ("bare python3 defers", ["python3"], False),
    ("python3 -m module defers", ["python3", "-m", "json.tool"], False),
    ("python3 script.py defers", ["python3", "script.py"], False),
    ("python3 -c with no script defers", ["python3", "-c"], False),
    ("python3 -c not first defers",
     ["python3", "-x", "-c", "print(1)"], False),
    ("python3 attached -cSCRIPT defers",
     ["python3", "-cprint(1)"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = python.classify(tokens)
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
