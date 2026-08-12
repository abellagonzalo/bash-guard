"""find: read-only unless it executes or mutates."""

import re

from .base import ALLOW, deny

NAMES = ("find",)

# APPEND-SAFE: only scans for specific mutating/executing flag tokens, never
# treats operand POSITION (e.g. "last operand") as meaningful, so appending
# more trailing operands (as `xargs`/`find -exec ... {} +` do) can't turn an
# ALLOW into something unsafe. See guard/registry.py.
APPEND_SAFE = True


def classify(tokens):
    for t in tokens[1:]:
        if re.fullmatch(r"-(exec|execdir|ok|okdir|delete|fprint|fprintf|fls)", t):
            return deny("find with a mutating/executing action")
    return ALLOW
