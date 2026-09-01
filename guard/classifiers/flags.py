"""Shared short-flag helpers.

curl, sort, and yq all need to detect a dangerous letter hidden inside a
bundled short-flag cluster (e.g. -rno, -iP, -sO) -- bundled_letters().

curl and psql both need to read a flag's value regardless of whether it's
spelled --name=value, --name value, -xvalue, or -x value -- flag_value().

Centralized here so this arithmetic has one copy instead of independently
drifting ones (see guard/quoting.py's module docstring for why that's
mattered before).
"""

import re
from typing import List, Optional, Tuple

_LEADING_LETTERS = re.compile(r"-([A-Za-z]+)")


def bundled_letters(token: str) -> Optional[str]:
    """If token is a single-dash short-flag cluster (e.g. '-rno'), return
    its letters ('rno'). Otherwise None (long flag, '-', or no leading '-')."""
    if not token.startswith("-") or token.startswith("--") or token == "-":
        return None
    m = _LEADING_LETTERS.match(token)
    return m.group(1) if m else None


def flag_value(
    tokens: List[str], i: int, attached: Optional[str]
) -> Tuple[Optional[str], int]:
    """tokens[i] is a flag already confirmed by the caller to take a value.
    `attached` is that value's inline portion -- the text after '=' for a
    long flag, or after the flag letter for a short flag -- or None if
    there wasn't one, in which case the following token supplies the value.
    Returns (value_or_None, next_i).
    """
    if attached is not None:
        return attached, i + 1
    j = i + 1
    if j < len(tokens):
        return tokens[j], j + 1
    return None, i + 1
