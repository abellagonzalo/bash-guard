"""yq: read-only unless it edits a file in place.

Both the mikefarah (Go) and kislyuk (Python) ``yq`` support ``-i`` / ``--inplace``
(``--in-place``), which rewrites the input file WITHOUT a shell redirect, so yq
can't live in the pure-read set. We defer whenever an in-place flag is present.

The in-place flag may be bundled with other boolean short flags (``-iP``), so we
defer on any single-dash token whose LEADING letter run contains lowercase
``i``. yq's ``-o`` is an OUTPUT-FORMAT flag (harmless) — NOT a file target like
``sort -o`` — and its ``-I`` (indent, uppercase) is distinct from ``-i``.
"""

import re

from .base import ALLOW, deny

NAMES = ("yq",)

_LEADING_LETTERS = re.compile(r"-([A-Za-z]+)")


def classify(tokens):
    for t in tokens[1:]:
        if t == "--inplace" or t == "--in-place":
            return deny("yq edits the file in place (-i/--inplace)")
        if t.startswith("-") and not t.startswith("--") and t != "-":
            m = _LEADING_LETTERS.match(t)
            if m and "i" in m.group(1):
                return deny("yq edits the file in place (-i/--inplace)")
    return ALLOW
