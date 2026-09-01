"""Shared short-flag-cluster helper.

curl, sort, and yq all need to detect a dangerous letter hidden inside a
bundled short-flag cluster (e.g. -rno, -iP, -sO). Centralized here so the
detection regex/logic has one copy instead of three independently drifting
ones.
"""

import re
from typing import Optional

_LEADING_LETTERS = re.compile(r"-([A-Za-z]+)")


def bundled_letters(token: str) -> Optional[str]:
    """If token is a single-dash short-flag cluster (e.g. '-rno'), return
    its letters ('rno'). Otherwise None (long flag, '-', or no leading '-')."""
    if not token.startswith("-") or token.startswith("--") or token == "-":
        return None
    m = _LEADING_LETTERS.match(token)
    return m.group(1) if m else None
