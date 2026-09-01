#!/usr/bin/env python3
"""Unit tests for guard/classifiers/psql.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_psql.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import psql  # noqa: E402

# (label, tokens, expected_ok) -- connection-info flags + a single safe
# SELECT/meta-command via -c.
CASES = [
    ("psql meta-command",
     ["psql", "-h", "h", "-U", "u", "-d", "d", "-c", "\\dt"], True),
    ("psql dsn positional select",
     ["psql", "host=localhost dbname=d", "-c", "select 1"], True),
    ("psql trailing semicolon ok",
     ["psql", "-c", "SELECT * FROM accounts;"], True),
    ("psql attached -c", ["psql", "-cselect 1"], True),
    ("psql long flags with =",
     ["psql", "--host=h", "--username=u", "--dbname=d", "--command=select 1"], True),
    ("psql expanded + meta with plus", ["psql", "-x", "-c", "\\dt+"], True),
    ("psql bare dbname/username positionals",
     ["psql", "mydb", "myuser", "-c", "select 1"], True),
    ("psql chained statement",
     ["psql", "-h", "h", "-c", "select 1; drop table x"], False),
    ("psql -f file", ["psql", "-f", "script.sql"], False),
    ("psql --file=", ["psql", "--file=script.sql"], False),
    ("psql non-select command", ["psql", "-c", "update x set y=1"], False),
    ("psql copy meta-command denied",
     ["psql", "-c", "\\copy (select 1) to stdout"], False),
    ("psql select into denied",
     ["psql", "-c", "select * into t from x"], False),
    ("psql cte smuggling insert denied",
     ["psql", "-c", "with x as (insert into t default values returning *) select * from x"],
     False),
    ("psql shell escape meta-command denied", ["psql", "-c", "\\! rm -rf /"], False),
    ("psql include file meta-command denied", ["psql", "-c", "\\i /etc/passwd"], False),
    ("psql multiple -c one bad",
     ["psql", "-c", "select 1", "-c", "delete from x"], False),
    ("psql ambiguous bundled flag", ["psql", "-xc", "select 1"], False),
    ("psql flag outside allowlist", ["psql", "-w", "-c", "select 1"], False),
    ("psql embedded newline denied", ["psql", "-c", "select 1\ndrop table x"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = psql.classify(tokens)
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
