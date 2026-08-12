"""Tokenize a command line and split it into control-operator segments.

FAIL SAFE: any uncertainty (substitution, subshell grouping, unbalanced quotes)
returns ``None`` so the caller defers. A pipeline/sequence is only ever
auto-allowed if every segment is independently read-only.
"""

import re
import shlex

from . import quoting, substitution

# Control operators that separate segments.
PIPE_SEP = {"|"}
SEQ_SEP = {"&&", "||", ";", "&"}

# Placeholder for an unquoted, backslash-escaped `;` (see
# _protect_escaped_semicolons). A real command string from the hook's stdin
# JSON can never carry a raw NUL, so this can't collide with user input.
_ESCAPED_SEMI = "\x00"

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
    four constructs the token list can no longer tell us about:

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

    **3. An unquoted ``#`` that starts a word** (a comment) **and 4. an
    unquoted ``<<``** (a heredoc). Bash treats the body of both as inert text;
    this walk and ``shlex`` (with ``commenters = ""``, see ``to_segments``)
    read it as ordinary command text, quotes included. An odd quote count
    inside such a bash-inert region shifts our quote phase and a second one
    shifts it back, so both sides end balanced, the fail-safe below never
    fires, and a later REAL command is swallowed as the contents of a string:

        echo hi # don't
        printf X # it's

    bash runs the ``printf``; we read a lone ``echo`` and auto-allow. Scoping
    the ``#`` to a word start (start of string, or after unquoted whitespace or
    one of ``;|&<>()``) is what keeps ``commenters = ""`` meaningful: a
    mid-token ``#`` is an ordinary character to bash too, so
    ``find . -name a#b -delete`` still lexes far enough to see the ``-delete``.
    ``\\`` + newline is line continuation — bash removes the pair, so the
    character BEFORE the backslash decides the word start, which is why that
    one escape preserves the flag instead of clearing it (``echo hi \\`` /
    newline / ``# don't`` is a comment to bash and hid the same payload).

    The ``<<`` test also catches ``<<-`` and ``<<<``; a here-string has no
    inert body and cannot desync on its own, but over-approximating costs one
    lookahead character and nothing else. Free in practice: of the 1123 unique
    auto-allowed commands in the audit log, none carries a word-start ``#`` or
    an unquoted ``<<`` — the two that match a naive grep have both inside
    ``"…"``, which this walk skips as quoted.

    FAIL SAFE: an unterminated quote returns True, so the caller defers rather
    than guessing at the quote state. A trailing lone backslash falls through
    here and is caught by the lexer's ``ValueError``, which is why this runs
    *before* lexing rather than replacing it.
    """
    i, n = 0, len(cmd)
    word_start = True            # bash reads `#` as a comment only at a word start
    while i < n:
        c = cmd[i]
        if c == "\\":            # escapes the next char (incl. `\(`, `\` newline)
            # `\` + newline is line continuation: bash deletes the pair, so the
            # character before it still decides whether a `#` starts a word.
            if cmd[i + 1:i + 2] != "\n":
                word_start = False
            i += 2
            continue
        if c == "$" and i + 1 < n and cmd[i + 1] == "'":
            return True          # ANSI-C quoting: escapes we mis-phase -> defer
        if c == "'":             # single quotes: literal through the next `'`
            end = quoting.skip_single(cmd, i)
            if end is None:
                return True
            i = end
            word_start = False   # a quoted region ends mid-word: `'a'#b` is literal
            continue
        if c == '"':             # double quotes: backslash still escapes
            end = quoting.skip_double(cmd, i)
            if end is None:
                return True
            i = end
            word_start = False
            continue
        if c in "()":
            return True
        if c == "#" and word_start:
            return True          # comment: bash ignores the quotes in its body
        if c == "<" and cmd[i + 1:i + 2] == "<":
            return True          # heredoc (`<<`, `<<-`) / here-string: ditto
        word_start = c in " \t\n;|&<>"
        i += 1
    return False


def _protect_escaped_semicolons(cmd):
    """Replace an unquoted, backslash-escaped ``\\;`` with a sentinel byte.

    Only called after ``_needs_raw_bailout`` has cleared ``cmd``, so quoting is
    known to be balanced and simple. Without this, ``find … -exec cmd {} \\;``
    loses its terminator: ``shlex`` resolves the escape to a bare ``;`` token
    indistinguishable from a real ``;`` separator, and ``to_segments`` splits
    the command in two, silently dropping the terminator (and anything meant
    to follow it). Quoted forms (``';'``, ``";"``) are left alone — same
    underlying desync, but out of scope here (see AGENTS.md).
    """
    out = []
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\" and cmd[i + 1:i + 2] == ";":
            out.append(_ESCAPED_SEMI)
            i += 2
            continue
        if c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if c == "'":
            j = cmd.find("'", i + 1)
            j = n - 1 if j < 0 else j
            out.append(cmd[i:j + 1])
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            while j < n and cmd[j] != '"':
                j += 2 if cmd[j] == "\\" else 1
            j = min(j, n - 1)
            out.append(cmd[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def to_segments(cmd):
    """Split ``cmd`` into segments (lists of tokens).

    Returns the list of segments, or ``None`` when the command must defer
    (command/process substitution, subshell grouping, ANSI-C quoting, a
    comment, a heredoc, or a lex error).
    """
    # Process substitution: out of scope, stays a hard, unconditional defer
    # regardless of quoting -- see guard/substitution.py's module docstring.
    if "<(" in cmd or ">(" in cmd:
        return None

    # Command substitution ($(...)/backtick): allowed iff its inner command
    # is itself provably read-only (see guard/substitution.py). An
    # unterminated span or a non-read-only inner command defers the WHOLE
    # outer command -- same None-return contract as every other bail-out
    # below, no new reason-string plumbing.
    cmd = substitution.desubstitute(cmd)
    if cmd is None:
        return None

    # Parenthesised subshells, `$'…'`, comments and heredocs: don't try to reason
    # about grouping, and don't lex a string whose quote phase we track
    # differently from bash. All are decided on the RAW string (see
    # _needs_raw_bailout) and only AFTER the substitution bail-out above, so any
    # paren reaching the lexer is either real grouping or an escaped/quoted
    # literal operand such as `find … \( -name a -o -name b \)`.
    if _needs_raw_bailout(cmd):
        return None

    # `find … -exec cmd {} \;` needs its escaped terminator to survive as a
    # literal `;` token without being mistaken for a segment separator below.
    cmd = _protect_escaped_semicolons(cmd)

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
        if t == _ESCAPED_SEMI:
            segment.append(";")
        elif t in PIPE_SEP or t in SEQ_SEP:
            segment = []
            segments.append(segment)
        else:
            segment.append(t)
    return segments
