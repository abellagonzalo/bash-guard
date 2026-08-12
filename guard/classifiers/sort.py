"""sort: read-only unless it writes its output to a file.

``sort`` normally streams to stdout, but ``-o FILE`` / ``--output FILE``
overwrites an arbitrary file WITHOUT a shell redirect, so it can't live in the
pure-read set. We defer whenever an output flag is present.

The short flag takes its argument attached (``-oFILE``), separated (``-o FILE``),
or bundled at the tail of a cluster (``-rno FILE``). We therefore defer on any
single-dash token whose LEADING letter run contains ``o`` (mirrors curl's
``_DANGEROUS_SHORT`` approach). No other sort short flag uses the letter ``o``,
so matching it has no harmless collision.
"""

import re

from .base import ALLOW, deny

NAMES = ("sort",)

# APPEND-SAFE (non `-o` forms): only inspects flags, never operand POSITION,
# so appending more trailing operands (as `xargs`/`find -exec ... {} +` do)
# can't turn an ALLOW into something unsafe. See guard/registry.py.
APPEND_SAFE = True

_LEADING_LETTERS = re.compile(r"-([A-Za-z]+)")


def classify(tokens):
    for t in tokens[1:]:
        if t == "--output" or t.startswith("--output="):
            return deny("sort writes its output to a file (-o/--output)")
        if t.startswith("-") and not t.startswith("--") and t != "-":
            m = _LEADING_LETTERS.match(t)
            if m and "o" in m.group(1):
                return deny("sort writes its output to a file (-o/--output)")
    return ALLOW
