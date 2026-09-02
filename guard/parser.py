"""Tokenize a command line and split it into control-operator segments.

FAIL SAFE: any uncertainty (substitution, subshell grouping, unbalanced quotes)
returns ``None`` so the caller defers. A pipeline/sequence is only ever
auto-allowed if every segment is independently read-only.
"""

import re
import shlex
from typing import List, Optional, Tuple

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


def strip_leading_assignments(tokens: List[str]) -> List[str]:
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


_HEREDOC_DELIM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _consume_quoted_heredoc(cmd: str, i: int) -> Optional[Tuple[str, int]]:
    """``cmd[i:i + 2] == "<<"``. Try to neutralize a *quoted-delimiter* heredoc.

    Returns ``(operator_text, resume_at)`` on success: ``operator_text`` is the
    verbatim ``<<'DELIM'``/``<<"DELIM"`` operator (left for ``shlex``/
    ``strip_redirects`` to tokenize normally) and ``resume_at`` is the index in
    ``cmd`` just past the delimiter's closing line, i.e. past the now-dropped
    body. Returns ``None`` for anything outside this narrow, provably-safe
    scope: ``<<-DELIM``/``<<<...``, an unquoted delimiter, an unterminated
    quote, a non-identifier delimiter, a non-whitespace character right after
    the closing quote, or no matching terminator line found -- the caller
    then bails out the whole command, same as before this carve-out existed.

    See AGENTS.md "How a command is judged" (the heredoc callout) for why a
    quoted heredoc body is safe to drop without scanning its contents.
    """
    n = len(cmd)
    j = i + 2
    if cmd[j:j + 1] in ("-", "<"):
        return None  # `<<-DELIM` / `<<<...`: out of scope
    quote = cmd[j:j + 1]
    if quote not in ("'", '"'):
        return None  # unquoted delimiter: still expansion-live
    end = quoting.skip_single(cmd, j) if quote == "'" else quoting.skip_double(cmd, j)
    if end is None:
        return None  # unterminated quote: fail safe
    if cmd[end:end + 1] not in ("", " ", "\t", "\n"):
        # e.g. `<<'EOF'x`: bash concatenates the quoted and unquoted parts
        # into one word ("EOFx"), a different (longer) true delimiter than
        # what's inside the quotes -- out of scope, don't guess at it.
        return None
    delim = cmd[j + 1:end - 1]
    if not _HEREDOC_DELIM.fullmatch(delim):
        return None  # exotic delimiter: out of narrow scope
    nl = cmd.find("\n", end)
    if nl < 0:
        return None  # operator with no possible body: malformed/truncated
    pos = nl + 1
    while True:
        line_end = cmd.find("\n", pos)
        line = cmd[pos:line_end] if line_end >= 0 else cmd[pos:n]
        if line == delim:
            return cmd[i:end], pos + len(delim)
        if line_end < 0:
            return None  # ran off the end without finding the terminator
        pos = line_end + 1


def _strip_quoted_heredocs(cmd: str) -> Optional[str]:
    """The rewritten ``cmd`` with every quoted-delimiter heredoc body dropped,
    or ``None`` if some ``<<`` in it can't be proven safe on the raw string.

    Runs FIRST in ``to_segments`` -- before ``substitution.desubstitute`` and
    ``_needs_raw_bailout`` -- because a heredoc body is unconditionally inert
    to bash and every other raw-string scanner here assumes it's looking at
    live text. On each unquoted, unescaped ``<<`` (tracked via the shared
    ``quoting.skip_single``/``skip_double``/``skip_ansi_c`` primitives),
    delegates to ``_consume_quoted_heredoc``; failure bails out the whole
    command.

    See AGENTS.md "How a command is judged" (the heredoc callout) for the bug
    this ordering fixes.
    """
    out = []
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if c == "$" and i + 1 < n and cmd[i + 1] == "'":
            end = quoting.skip_ansi_c(cmd, i + 1)
            if end is None:
                return None
            out.append(cmd[i:end])
            i = end
            continue
        if c == "'":
            end = quoting.skip_single(cmd, i)
            if end is None:
                return None
            out.append(cmd[i:end])
            i = end
            continue
        if c == '"':
            end = quoting.skip_double(cmd, i)
            if end is None:
                return None
            out.append(cmd[i:end])
            i = end
            continue
        if c == "<" and cmd[i + 1:i + 2] == "<":
            heredoc = _consume_quoted_heredoc(cmd, i)
            if heredoc is None:
                return None
            operator_text, i = heredoc
            out.append(operator_text)
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _needs_raw_bailout(cmd: str) -> bool:
    """True if ``cmd`` must defer on evidence only the RAW string carries.

    Only reached after ``_strip_quoted_heredocs`` has resolved every ``<<`` in
    ``cmd``, so this walk needs no heredoc case of its own. Walks the string
    tracking bash's quoting forms (``\\c``, ``'...'`` with no escaping,
    ``"..."`` where ``\\`` escapes) and returns ``True`` on a real
    unquoted/unescaped subshell paren, an ANSI-C ``$'...'`` quote, or a
    word-start ``#`` comment -- three constructs the token list can no longer
    tell us about once lexed. FAIL SAFE: an unterminated quote also returns
    ``True`` (defer), never guesses at quote state.

    See AGENTS.md "How a command is judged" (the subshell, ANSI-C ``$'...'``,
    and word-start ``#`` callouts) for why each construct can't be reasoned
    about post-tokenization, their exploit payloads, and audit-log stats.
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
        word_start = c in " \t\n;|&<>"
        i += 1
    return False


def _protect_escaped_semicolons(cmd: str) -> str:
    """Replace an unquoted, backslash-escaped ``\\;`` with a sentinel byte,
    turn a bare unquoted newline into a real ``;`` separator, and delete a
    ``\\`` + newline line continuation outright.

    Only called after ``_strip_quoted_heredocs``/``_needs_raw_bailout`` have
    cleared ``cmd``, so quoting is known to be balanced and simple. Quoted
    forms (``';'``, ``";"``) are left alone -- same underlying desync, but a
    distinct, pre-existing issue.

    See AGENTS.md "How a command is judged" (the bare-newline and
    ``find -exec ... \\;`` callouts) for the false-allow bugs this rewrite
    fixes.
    """
    out = []
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\" and cmd[i + 1:i + 2] == ";":
            out.append(_ESCAPED_SEMI)
            i += 2
            continue
        if c == "\\" and cmd[i + 1:i + 2] == "\n":
            i += 2  # line continuation: bash deletes the pair, no separator
            continue
        if c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if c == "\n":
            out.append(";")
            i += 1
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


def to_segments(cmd: str) -> Optional[List[List[str]]]:
    """Split ``cmd`` into segments (lists of tokens).

    Returns the list of segments, or ``None`` when the command must defer
    (command/process substitution, subshell grouping, ANSI-C quoting, a
    comment, an unquoted/``<<-``/here-string heredoc, an unterminated or
    non-identifier quoted-delimiter heredoc, or a lex error). See
    ``_strip_quoted_heredocs`` for why heredoc bodies are resolved first,
    before anything else below looks at the raw string.
    """
    # Process substitution: out of scope, stays a hard, unconditional defer
    # regardless of quoting -- see guard/substitution.py's module docstring.
    if "<(" in cmd or ">(" in cmd:
        return None

    # Heredoc bodies are unconditionally inert to bash and MUST be resolved
    # before anything else touches the raw string: both desubstitute() and
    # _needs_raw_bailout() below assume they're looking at live text, and a
    # stray quote or `$(` sitting inertly inside an unstripped body can
    # desync either of them (see _strip_quoted_heredocs's docstring for the
    # exact bug this order avoids). A quoted-delimiter heredoc's body is
    # dropped; anything else `<<`-shaped (unquoted, `<<-`, `<<<`,
    # unterminated, non-identifier delimiter) defers the WHOLE command here,
    # same as it always has.
    stripped = _strip_quoted_heredocs(cmd)
    if stripped is None:
        return None
    cmd = stripped

    # Command substitution ($(...)/backtick): allowed iff its inner command
    # is itself provably read-only (see guard/substitution.py). An
    # unterminated span or a non-read-only inner command defers the WHOLE
    # outer command -- same None-return contract as every other bail-out
    # below, no new reason-string plumbing.
    desubstituted = substitution.desubstitute(cmd)
    if desubstituted is None:
        return None
    cmd = desubstituted

    # Parenthesised subshells, `$'…'`, and comments: don't try to reason
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
    segment: List[str] = []
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
