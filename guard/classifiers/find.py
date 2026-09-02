"""find: read-only unless it executes or mutates.

`-exec cmd … {} \\;` / `-exec cmd … {} +` payloads are extracted and
classified recursively through the shared APPEND_SAFE gate in
`classifiers/wrapped.py`; every other executing/mutating action stays a hard
deny.
"""

import re
from typing import List, Optional

from .base import ALLOW, Result, deny
from .wrapped import classify_wrapped

NAMES = ("find",)

# APPEND-SAFE: only scans for specific mutating/executing flag tokens, never
# treats operand POSITION (e.g. "last operand") as meaningful, so appending
# more trailing operands (as `xargs`/`find -exec ... {} +` do) can't turn an
# ALLOW into something unsafe. See guard/registry.py.
APPEND_SAFE = True

_HARD_DENY = re.compile(r"-(execdir|ok|okdir|delete|fprint|fprintf|fls)")


def classify(tokens: List[str]) -> Result:
    args = tokens[1:]
    i, n = 0, len(args)
    while i < n:
        t = args[i]

        if _HARD_DENY.fullmatch(t):
            return deny("find with a mutating/executing action")

        if t == "-exec":
            end = _find_terminator(args, i + 1)
            if end is None:
                return deny("find -exec with no ; or + terminator")
            payload = args[i + 1:end]

            result = classify_wrapped(payload, context="find -exec")
            if not result.ok:
                return result

            i = end + 1
            continue

        i += 1
    return ALLOW


def _find_terminator(args: List[str], start: int) -> Optional[int]:
    """Index of the `;` or `+` ending a `-exec` clause starting at ``start``."""
    for j in range(start, len(args)):
        if args[j] in (";", "+"):
            return j
    return None
