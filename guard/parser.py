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


_HEREDOC_DELIM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _consume_quoted_heredoc(cmd, i):
    """``cmd[i:i + 2] == "<<"``. Try to neutralize a *quoted-delimiter* heredoc.

    Returns ``(operator_text, resume_at)`` on success: ``operator_text`` is
    ``cmd[i:end]`` (the ``<<'DELIM'``/``<<"DELIM"`` operator, verbatim — left
    for ``shlex``/``strip_redirects`` to tokenize normally, since
    ``guard/redirects.py``'s ``REDIR_IN`` already lists ``"<<"``) and
    ``resume_at`` is the index in ``cmd`` just past the delimiter's closing
    line, i.e. past the now-dropped body. Returns ``None`` for anything out of
    this narrow, provably-safe scope — the caller then bails out exactly as it
    did before this carve-out existed:

    * ``<<-DELIM`` or ``<<<...`` (a third ``<``): tab-stripping and
      here-strings are out of scope — no delimiter-matching subtlety worth it.
    * An unquoted delimiter: still expansion-live, still needs the blanket
      bail-out.
    * An unterminated quote, or a quoted delimiter that isn't a plain
      identifier (``[A-Za-z_][A-Za-z0-9_]*`` — rejects embedded spaces, ``$``,
      punctuation): deliberately narrow scope, matches every real-world
      example that motivated this (``EOF``, ``PYEOF``, ``SQL``, ...).
    * A non-whitespace character directly after the closing quote (e.g.
      ``<<'EOF'x``): bash concatenates quoted and unquoted word parts, so the
      TRUE delimiter would be ``EOFx``, not the ``EOF`` inside the quotes —
      rather than guess at string concatenation rules, bail out.
    * No matching terminator line found (a line that is *exactly* the
      delimiter — no leading/trailing characters, since ``<<-`` is excluded
      there's no tab-stripping ambiguity): unterminated heredoc, same
      "never guess, defer" contract as ``quoting.skip_single``/``skip_double``
      returning ``None`` elsewhere in this file.

    Bash gives a quoted heredoc delimiter a hard guarantee a static scanner
    can lean on: the body undergoes **zero expansion** — no ``$var``, no
    backticks, no further quote processing — so once its span is located
    structurally (by delimiter line, not by scanning its contents), there is
    no live text left inside it to quote-desync on. That is what makes this
    safe where the general ``<<`` bail-out (see below) is not.
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


def _strip_quoted_heredocs(cmd):
    """The rewritten ``cmd`` with every quoted-delimiter heredoc body dropped,
    or ``None`` if some ``<<`` in it can't be proven safe on the RAW string.

    Runs FIRST in ``to_segments`` — *before* ``substitution.desubstitute`` and
    ``_needs_raw_bailout`` — because a heredoc body is unconditionally inert to
    bash (no quote processing, no ``$(...)``/backtick expansion at all once
    the delimiter is quoted) and every other raw-string scanner in this
    package assumes it's looking at live text. Stripping bodies here first
    means neither of those later passes ever has to be heredoc-aware: nothing
    downstream can be confused by a stray quote or ``$(`` sitting inertly
    inside a body it was never going to touch. (An earlier version folded
    this into the later paren/comment walk instead; a heredoc body containing
    an apostrophe -- e.g. ``cat <<'EOF'\\nit's\\nEOF`` -- then reached
    ``desubstitute`` BEFORE its body was stripped, and desubstitute's own
    independent quote walk misread the apostrophe as a real quote-open and
    hunted for a closing ``'`` that was never coming. Exactly the "two
    independent quote walks drift out of sync" bug class ``guard/quoting.py``
    warns about — the fix is to never let two passes read the same live-vs-
    inert text differently, not to make them agree by accident.)

    On each unquoted, unescaped ``<<`` (tracking quotes via the same shared
    ``quoting.skip_single``/``skip_double``/``skip_ansi_c`` primitives every
    other scanner here uses — never a fourth, independently-derived quote
    walk), delegates to ``_consume_quoted_heredoc``. Success: its body is
    dropped from the output and the walk resumes right after the delimiter
    line. Failure (anything outside that function's narrow scope: unquoted
    delimiter, ``<<-``, ``<<<``, unterminated, non-identifier delimiter, no
    matching terminator line) bails out the WHOLE command — the exact same
    blanket ``<<`` defer this hook always had, just now decided in the first
    pass instead of a later one. A quote or ``$'…'`` span with no ``<<``
    inside it is left completely untouched; bailing on those (real subshell
    parens, ANSI-C desync, word-start comments) is later passes' job, not
    this one's — this pass only ever answers "is every ``<<`` in here a
    provably-safe quoted heredoc."
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


def _needs_raw_bailout(cmd):
    """True if ``cmd`` must defer on evidence only the RAW string carries.

    Only reached after ``_strip_quoted_heredocs`` has already resolved every
    ``<<`` in ``cmd`` (stripped its body, or bailed the whole command) — so
    unlike its own past self, this walk no longer needs any ``<<`` case of
    its own; any ``<<`` still present at this point is already a proven-safe,
    body-stripped heredoc operator that ``shlex``/``strip_redirects`` (see
    ``guard/redirects.py``'s ``REDIR_IN``) can tokenize like any other
    redirect, no special-casing needed here.

    Walks the string tracking bash's quoting forms — ``\\c``, ``'…'`` (where a
    backslash is NOT an escape), and ``"…"`` (where it is) — and bails out on
    three constructs the token list can no longer tell us about:

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

    **3. An unquoted ``#`` that starts a word** (a comment). Bash treats a
    comment body as inert text; this walk and ``shlex`` (with
    ``commenters = ""``, see ``to_segments``) read it as ordinary command
    text, quotes included. An odd quote count inside such a bash-inert region
    shifts our quote phase and a second one shifts it back, so both sides end
    balanced, the fail-safe below never fires, and a later REAL command is
    swallowed as the contents of a string:

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
    (A heredoc body is the same class of bash-inert-but-live-to-us hazard —
    handled earlier, by ``_strip_quoted_heredocs`` running before this
    function, or the older blanket ``<<`` bail-out for anything that isn't a
    quoted-delimiter heredoc; see that function's docstring.)

    FAIL SAFE: an unterminated quote returns ``None``, so the caller defers
    rather than guessing at the quote state. A trailing lone backslash falls
    through here and is caught by the lexer's ``ValueError``, which is why
    this runs *before* lexing rather than replacing it.
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


def _protect_escaped_semicolons(cmd):
    """Replace an unquoted, backslash-escaped ``\\;`` with a sentinel byte, turn
    a bare unquoted newline into a real ``;`` separator, and delete a ``\\`` +
    newline line continuation outright.

    Only called after ``_strip_quoted_heredocs``/``_needs_raw_bailout`` have
    cleared ``cmd``, so quoting is known to be balanced and simple.

    Without the ``\\;`` handling, ``find … -exec cmd {} \\;`` loses its
    terminator: ``shlex`` resolves the escape to a bare ``;`` token
    indistinguishable from a real ``;`` separator, and ``to_segments`` splits
    the command in two, silently dropping the terminator (and anything meant
    to follow it). Quoted forms (``';'``, ``";"``) are left alone — same
    underlying desync, but out of scope here (see AGENTS.md).

    Without the newline handling, ``shlex`` (``whitespace_split=True``) treats
    a bare newline as ordinary whitespace, not a separator, so two unrelated
    statements on two lines — e.g. ``cd /tmp`` / newline / ``rm -rf /tmp/x`` —
    collapse into ONE segment classified only by the first word. A classifier
    like ``cd``'s that ignores its own arguments (``classifiers/readonly.py``,
    ``APPEND_SAFE``) then auto-allows the whole thing, silently swallowing the
    second, unrelated, unvetted statement as bogus trailing "arguments" — bash
    itself, of course, runs it as a separate command. Converting the bare
    newline to ``;`` here — the same real separator bash treats it as — lets
    the existing segment-splitting machinery below catch it. A ``\\`` +
    newline is a genuine line continuation, not a separator, so bash deletes
    the pair and joins the lines with nothing in between; that's the one case
    a bare newline must NOT become a ``;``.
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


def to_segments(cmd):
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
    cmd = _strip_quoted_heredocs(cmd)
    if cmd is None:
        return None

    # Command substitution ($(...)/backtick): allowed iff its inner command
    # is itself provably read-only (see guard/substitution.py). An
    # unterminated span or a non-read-only inner command defers the WHOLE
    # outer command -- same None-return contract as every other bail-out
    # below, no new reason-string plumbing.
    cmd = substitution.desubstitute(cmd)
    if cmd is None:
        return None

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
