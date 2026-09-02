"""yq: read-only unless it edits a file in place.

Both the mikefarah (Go) and kislyuk (Python) ``yq`` support ``-i`` / ``--inplace``
(``--in-place``), which rewrites the input file WITHOUT a shell redirect, so yq
can't live in the pure-read set. We defer whenever an in-place flag is present.

The in-place flag may be bundled with other boolean short flags (``-iP``), so we
defer on any single-dash token whose LEADING letter run contains lowercase
``i``. yq's ``-o`` is an OUTPUT-FORMAT flag (harmless) — NOT a file target like
``sort -o`` — and its ``-I`` (indent, uppercase) is distinct from ``-i``.
"""

from typing import List

from .base import ALLOW, Result, deny
from .flags import bundled_letters

NAMES = ("yq",)

# APPEND-SAFE (non `-i` forms): only inspects flags, never operand POSITION,
# so appending more trailing operands (as `xargs`/`find -exec ... {} +` do)
# can't turn an ALLOW into something unsafe. See guard/registry.py.
APPEND_SAFE = True


def classify(tokens: List[str]) -> Result:
    for t in tokens[1:]:
        if t == "--inplace" or t == "--in-place":
            return deny("yq edits the file in place (-i/--inplace)")
        letters = bundled_letters(t)
        if letters and "i" in letters:
            return deny("yq edits the file in place (-i/--inplace)")
    return ALLOW
