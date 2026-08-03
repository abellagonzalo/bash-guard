"""Tokenize a command line and split it into control-operator segments.

FAIL SAFE: any uncertainty (substitution, subshell grouping, unbalanced quotes)
returns ``None`` so the caller defers. A pipeline/sequence is only ever
auto-allowed if every segment is independently read-only.
"""

import re
import shlex

# Control operators that separate segments.
PIPE_SEP = {"|"}
SEQ_SEP = {"&&", "||", ";", "&"}

# A leading ``NAME=value`` environment assignment (the command name, if any,
# follows it). Shell only treats ``NAME=...`` as an assignment in this leading
# position, so we stop at the first token that isn't one.
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def strip_leading_assignments(tokens):
    """Drop leading ``NAME=value`` env assignments from a segment.

    ``FOO=1 BAR=2 grep x`` -> ``["grep", "x"]``. Stops at the first
    non-assignment token (the command), so later operands like grep's ``x=y``
    are never dropped. Safe because command/process substitution is already
    rejected in ``to_segments``, so an assignment value can't smuggle in a
    command.
    """
    i = 0
    while i < len(tokens) and _ASSIGNMENT.match(tokens[i]):
        i += 1
    return tokens[i:]


def to_segments(cmd):
    """Split ``cmd`` into segments (lists of tokens).

    Returns the list of segments, or ``None`` when the command must defer
    (command/process substitution, subshell grouping, or a lex error).
    """
    # Command / process substitution: cannot reason about inner command -> defer.
    if "$(" in cmd or "`" in cmd or "<(" in cmd or ">(" in cmd:
        return None

    lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";()<>|&")
    lexer.whitespace_split = True
    # Disable comment handling: otherwise shlex silently drops everything after
    # an unquoted '#', which could HIDE a mutating flag (e.g.
    # `find . -name a#b -delete` -> tokens stop before `-delete`) and cause a
    # false "allow". A '#' is now just an ordinary character in a token.
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        # Unbalanced quotes etc. -> let the normal flow prompt.
        return None

    # Parenthesised subshells: don't try to reason about grouping.
    if "(" in tokens or ")" in tokens:
        return None

    # Split into segments on any control operator; every segment must be safe.
    segment = []
    segments = [segment]
    for t in tokens:
        if t in PIPE_SEP or t in SEQ_SEP:
            segment = []
            segments.append(segment)
        else:
            segment.append(t)
    return segments
