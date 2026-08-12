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


def _needs_raw_bailout(cmd):
    """True if ``cmd`` must defer on evidence only the RAW string carries.

    Walks the string tracking bash's quoting forms — ``\\c``, ``'…'`` (where a
    backslash is NOT an escape), and ``"…"`` (where it is) — and bails out on
    two constructs the token list can no longer tell us about:

    **1. An unquoted, unescaped ``(`` or ``)``** — real subshell grouping. This
    MUST be decided on the raw string: ``shlex`` resolves the escape before we
    ever see the token, so ``\\(`` (a literal ``find`` operand) and a real
    subshell ``(`` are indistinguishable once lexed:

        lex(r'find . \\( -name "*.kt" \\)') -> ['find', '.', '(', '-name', ...]

    **2. An ANSI-C ``$'…'`` quote.** Inside it bash *does* let a backslash
    escape — including ``\\'`` — while this walk and ``shlex`` both read that
    ``'`` as the closing quote. Two crafted occurrences shift the quote phase
    and shift it back, so both sides end balanced and the unterminated-quote
    fail-safe below never fires:

        echo $'\\''; rm -rf /tmp/x; echo \\'

    bash runs the ``rm``; we read ``; rm -rf /tmp/x; echo `` as the *contents*
    of a string and auto-allow an ``echo``. It is not paren-specific — the same
    payload hides behind ``shlex`` with no paren anywhere — so it can only be
    fixed by refusing ``$'…'`` outright. Cheap in practice: zero of the 2076
    commands in the audit log use it (the ``$'`` hits there are all a regex
    ``$`` anchor before a closing quote, which this walk skips as quoted).
    ``$"…"`` needs no such case — it quotes exactly like ``"…"``.

    FAIL SAFE: an unterminated quote returns True, so the caller defers rather
    than guessing at the quote state. A trailing lone backslash falls through
    here and is caught by the lexer's ``ValueError``, which is why this runs
    *before* lexing rather than replacing it.

    NOT covered: bash ignores quotes inside a ``#`` comment or a heredoc body,
    but this walk (and shlex, with ``commenters = ""``) does not. An odd quote
    count inside such a bash-inert region shifts our phase the same way and can
    swallow a later real command. That hole predates this function and is
    paren-independent; it needs its own ``#``/``<<`` bail-out.
    """
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\":            # escapes the next char (incl. `\(`, `\` newline)
            i += 2
            continue
        if c == "$" and i + 1 < n and cmd[i + 1] == "'":
            return True          # ANSI-C quoting: escapes we mis-phase -> defer
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
    (command/process substitution, subshell grouping, ANSI-C quoting, or a lex
    error).
    """
    # Command / process substitution: cannot reason about inner command -> defer.
    if "$(" in cmd or "`" in cmd or "<(" in cmd or ">(" in cmd:
        return None

    # Parenthesised subshells and `$'…'`: don't try to reason about grouping, and
    # don't lex a string whose escapes we phase differently from bash. Both are
    # decided on the RAW string (see _needs_raw_bailout) and only AFTER the
    # substitution bail-out above, so any paren reaching the lexer is either real
    # grouping or an escaped/quoted literal operand such as
    # `find … \( -name a -o -name b \)`.
    if _needs_raw_bailout(cmd):
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
