"""find: read-only unless it executes or mutates.

`-exec cmd … {} \\;` / `-exec cmd … {} +` payloads are extracted and classified
recursively through the same APPEND_SAFE gate as `xargs.py`; every other
executing/mutating action stays a hard deny.
"""

import re

from .base import ALLOW, deny

NAMES = ("find",)

# APPEND-SAFE: only scans for specific mutating/executing flag tokens, never
# treats operand POSITION (e.g. "last operand") as meaningful, so appending
# more trailing operands (as `xargs`/`find -exec ... {} +` do) can't turn an
# ALLOW into something unsafe. See guard/registry.py.
APPEND_SAFE = True

_HARD_DENY = re.compile(r"-(execdir|ok|okdir|delete|fprint|fprintf|fls)")


def classify(tokens):
    # Lazy import: registry.py imports this module (to read NAMES/classify)
    # BEFORE it finishes building CLASSIFIERS/APPEND_SAFE, so a top-level
    # `from ..registry import ...` would raise ImportError on a
    # partially-initialized module. classify() only runs per-request, long
    # after registry.py has finished executing at process startup, so by then
    # the import is just a plain attribute lookup. See classifiers/xargs.py.
    from ..registry import APPEND_SAFE as _APPEND_SAFE, CLASSIFIERS

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
            if not payload:
                return deny("find -exec with no wrapped command")

            wrapped_cmd = payload[0]
            wrapped_classify = CLASSIFIERS.get(wrapped_cmd)
            if wrapped_classify is None:
                return deny(f"find -exec wraps unknown command: {wrapped_cmd}")
            if not _APPEND_SAFE.get(wrapped_cmd, False):
                return deny(
                    "find -exec wraps a command whose classifier isn't "
                    f"append-safe: {wrapped_cmd}"
                )

            ok, reason = wrapped_classify(payload)
            if not ok:
                return deny(reason)

            i = end + 1
            continue

        i += 1
    return ALLOW


def _find_terminator(args, start):
    """Index of the `;` or `+` ending a `-exec` clause starting at ``start``."""
    for j in range(start, len(args)):
        if args[j] in (";", "+"):
            return j
    return None
