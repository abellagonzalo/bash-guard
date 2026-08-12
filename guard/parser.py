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


def _has_unquoted_paren(cmd):
    """True if ``cmd`` contains a ``(`` or ``)`` outside quotes and unescaped.

    This MUST be decided on the raw string. ``shlex`` resolves the escape before
    we ever see the token, so ``\\(`` (a literal ``find`` operand) and a real
    subshell ``(`` are indistinguishable in the token list:

        lex(r'find . \\( -name "*.kt" \\)') -> ['find', '.', '(', '-name', ...]

    Walks the string tracking bash's three quoting forms — ``\\c``, ``'…'``
    (where a backslash is NOT an escape), and ``"…"`` (where it is).

    ``$'…'`` / ``$"…"`` get no special case. ``$'a\\'b'`` really does shift our
    quote phase relative to bash's (bash consumes the escaped ``'``, we end the
    quote there), but every such shift leaves either an unterminated quote or an
    unquoted paren, so it resolves to True — a defer. Fail safe in the direction
    we need.

    FAIL SAFE: an unterminated quote returns True, so the caller defers rather
    than guessing at the quote state. A trailing lone backslash falls through
    here and is caught by the lexer's ``ValueError``, which is why this runs
    *before* lexing rather than replacing it.

    NOT covered: bash ignores quotes inside a ``#`` comment or a heredoc body,
    but this walk (and shlex, with ``commenters = ""``) does not. An odd quote
    count inside such a bash-inert region shifts our phase and can swallow a
    later real command. That hole predates this function and is paren-
    independent; it needs its own ``#``/``<<`` bail-out.
    """
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\":            # escapes the next char (incl. `\(`, `\` newline)
            i += 2
            continue
        if c == "'":             # single quotes: literal through the next `'`
            j = cmd.find("'", i + 1)
            if j < 0:
                return True
            i = j + 1
            continue
        if c == '"':             # double quotes: backslash still escapes
            i += 1
            while i < n and cmd[i] != '"':
                i += 2 if cmd[i] == "\\" else 1
            if i >= n:
                return True
            i += 1
            continue
        if c in "()":
            return True
        i += 1
    return False


def to_segments(cmd):
    """Split ``cmd`` into segments (lists of tokens).

    Returns the list of segments, or ``None`` when the command must defer
    (command/process substitution, subshell grouping, or a lex error).
    """
    # Command / process substitution: cannot reason about inner command -> defer.
    if "$(" in cmd or "`" in cmd or "<(" in cmd or ">(" in cmd:
        return None

    # Parenthesised subshells: don't try to reason about grouping. Checked on the
    # RAW string (see _has_unquoted_paren) and only AFTER the substitution
    # bail-out above, so any paren reaching here is either real grouping or an
    # escaped/quoted literal operand such as `find … \( -name a -o -name b \)`.
    if _has_unquoted_paren(cmd):
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
