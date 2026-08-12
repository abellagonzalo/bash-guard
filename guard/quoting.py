"""Shared raw-string quote-span primitives.

Bash quoting has exactly three "opaque span" forms this hook cares about:
``'…'`` (no escaping at all), ``"…"`` (backslash escapes the next char), and
``$'…'`` (same escaping as ``"…"``, but written after a ``$``). Several
raw-string scanners in this package (``parser.py``'s ``_needs_raw_bailout``,
``substitution.py``'s span finders) all need to skip past one of these spans
without re-deriving the same char-walk — a prior source of bugs here (see
commits 4e1c601, 49e580d: two independent, subtly different quote walks each
hid a real command behind a crafted desync). These three functions are the
single implementation every caller shares.

Each takes ``cmd`` and the index of the OPENING quote character, and returns
the index just past the matching CLOSING quote, or ``None`` if the span never
closes (caller must then defer — never guess at the quote state).
"""


def skip_single(cmd, i):
    """cmd[i] == "'". No escaping inside — the next `'` always closes it."""
    j = cmd.find("'", i + 1)
    if j < 0:
        return None
    return j + 1


def skip_double(cmd, i):
    """cmd[i] == '"'. "\\" escapes the next char, including "\\""."""
    n = len(cmd)
    j = i + 1
    while j < n and cmd[j] != '"':
        j += 2 if cmd[j] == "\\" else 1
    if j >= n:
        return None
    return j + 1


def skip_ansi_c(cmd, i):
    """cmd[i] == "'" opening a $'…' (caller has already matched the "$").

    Same escaping rule as skip_double, including "\\'" — bash lets a
    backslash escape the closing quote inside $'…', unlike plain '…'.
    """
    n = len(cmd)
    j = i + 1
    while j < n and cmd[j] != "'":
        j += 2 if cmd[j] == "\\" else 1
    if j >= n:
        return None
    return j + 1
