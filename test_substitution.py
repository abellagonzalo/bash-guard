#!/usr/bin/env python3
"""Unit tests for guard/substitution.py and guard/quoting.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``desubstitute(cmd) -> str | None`` and the shared quote-span
primitives directly against exact expected strings/indices -- catches
off-by-one/index bugs the end-to-end suite can't localize. Stdlib-only, like
the sibling suites.

    python3 test_substitution.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from guard import quoting  # noqa: E402
from guard.substitution import PLACEHOLDER, desubstitute  # noqa: E402

P = PLACEHOLDER

# (label, cmd, expected_result)  -- expected_result is a string or None.
DESUBSTITUTE_CASES = [
    ("plain $(...)", "echo $(echo hi)", f"echo {P}"),
    ("plain backtick", "echo `echo hi`", f"echo {P}"),
    ("substitution inside double quotes",
     'echo "$(git rev-parse HEAD)"', f'echo "{P}"'),
    ("nested $(...) collapses to one placeholder",
     "echo $(echo $(echo nested))", f"echo {P}"),
    ("substitution mid-word",
     "grep foo$(echo _bar) file", f"grep foo{P} file"),
    ("substitution inside a pipeline segment",
     "git log | grep $(echo FIX)", f"git log | grep {P}"),
    ("assignment RHS then use (issue #4's own example)",
     "f=$(find . -name '*.kt'); grep -l foo \"$f\"",
     f'f={P}; grep -l foo "$f"'),
    ("two independent substitutions",
     "echo $(echo a) $(echo b)", f"echo {P} {P}"),
    ("escaped $( is not an opener",
     r"echo \$(rm x)", r"echo \$(rm x)"),
    (r"escaped backtick is not an opener",
     r"echo \`rm x\`", r"echo \`rm x\`"),
    ("substitution inside single quotes is inert (not expanded)",
     "echo '$(rm x)'", "echo '$(rm x)'"),
    ("non-read-only inner command -> defer", "echo $(rm x)", None),
    ("non-read-only inner command, backtick -> defer", "echo `rm x`", None),
    ("unterminated $( -> defer", "echo $(", None),
    ("unterminated backtick -> defer", "echo `echo hi", None),
    ("unbalanced quote inside span -> defer",
     "echo $(echo 'unterminated)", None),
    ("unknown command inside span -> defer", "echo $(rsync -a a b)", None),
    ("find -exec inside span still append-safety-gated",
     r"echo $(find . -exec rm {} \;)", None),
    (r"backtick containing a nested quoted backtick (documented limitation)",
     r"""echo `echo '`'`""", None),
]

# (label, fn, cmd, i, expected_end)  -- expected_end is an int or None.
QUOTE_SPAN_CASES = [
    ("skip_single ordinary", quoting.skip_single, "'abc'", 0, 5),
    ("skip_single unterminated", quoting.skip_single, "'abc", 0, None),
    ("skip_double ordinary", quoting.skip_double, '"abc"', 0, 5),
    ("skip_double with escape", quoting.skip_double, r'"a\"b"', 0, 6),
    ("skip_double unterminated", quoting.skip_double, '"abc', 0, None),
    # The historical ANSI-C desync payload: $'\'' is a single, self-contained
    # 5-char span (open quote, escaped quote, close quote) -- skip_ansi_c must
    # return the index PAST the true closing quote (5), not stop early at the
    # escaped one.
    ("skip_ansi_c desync payload", quoting.skip_ansi_c, r"'\''", 0, 4),
    ("skip_ansi_c unterminated", quoting.skip_ansi_c, r"'\'", 0, None),
]


def main():
    failures = []

    for label, cmd, expected in DESUBSTITUTE_CASES:
        got = desubstitute(cmd)
        ok = got == expected
        status = "ok" if ok else "FAIL"
        if not ok:
            failures.append((label, cmd, got, expected))
        print(f"[{status}] {label}: desubstitute({cmd!r}) -> {got!r}")

    for label, fn, cmd, i, expected in QUOTE_SPAN_CASES:
        got = fn(cmd, i)
        ok = got == expected
        status = "ok" if ok else "FAIL"
        if not ok:
            failures.append((label, cmd, got, expected))
        print(f"[{status}] {label}: {fn.__name__}({cmd!r}, {i}) -> {got!r}")

    print()
    total = len(DESUBSTITUTE_CASES) + len(QUOTE_SPAN_CASES)
    if failures:
        print(f"{len(failures)}/{total} FAILED:")
        for label, cmd, got, want in failures:
            print(f"  {label}: got {got!r}, want {want!r} (input={cmd!r})")
        return 1
    print(f"All {total} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
