"""Command substitution (``$(...)`` / backtick): allowed iff read-only.

Process substitution (``<(...)``, ``>(...)``) is explicitly OUT OF SCOPE and
stays a hard, unconditional defer -- see the raw-substring check in
``guard/parser.py``, run before this module is ever reached.

Bash lets ``$(...)``/backtick expand both unquoted and inside ``"..."`` (but
NOT inside ``'...'`` or an ANSI-C ``$'...'``, which suppress all expansion).
This module walks the raw command tracking exactly that: a ``'...'``/
``$'...'`` span is skipped atomically (its content, including any
``$(...)``/backtick inside, is never live); a ``"..."`` span toggles a flag
but is still scanned character-by-character, since ``$(...)``/backtick ARE
live inside it.

Each span found is recursively evaluated through ``guard.cli.evaluate()`` --
the SAME segment/classifier pipeline used for the top-level command, so an
inner pipeline, its own nested substitutions, etc. "just work" through
ordinary recursion. If the inner command isn't provably read-only (or the
span never closes), the WHOLE outer command defers -- same ``None``-return
contract as every other bail-out in ``guard/parser.py``, no new
reason-string plumbing.

Once an inner command is proven read-only, its span is replaced with a
fixed, metacharacter-free ``PLACEHOLDER`` before the outer command continues
through the ordinary ``to_segments``/``shlex`` pipeline. This is no riskier
than the tool's EXISTING, unguarded acceptance of an unquoted ``$VAR``
expansion: once a command is known not to mutate anything, treating its
stdout as an opaque runtime value is the same class of "unknown value" a
classifier already has to fail closed on for any unexpected operand shape.

Known, accepted limitations (fail closed -> extra defer, never a false
allow):

* Nested quotes INSIDE a backtick span are not tracked (backticks don't
  nest); a literal backtick inside a nested quote is misread as the
  terminator. The truncated remainder then almost always contains an
  unbalanced quote, which ``parser._needs_raw_bailout``'s unterminated-quote
  check (or ``shlex``'s own ``ValueError``) catches.
* ``$((...))`` arithmetic expansion is not special-cased -- it reads as
  ``$(`` with inner text ``(expr)``, which fails the bare-paren check when
  THAT is recursively parsed, so it always defers. No classifier understands
  arithmetic; this is expected, not a regression.
* Nested substitution drives real Python recursion (``desubstitute ->
  evaluate -> to_segments -> desubstitute -> ...``); pathologically deep
  nesting could raise ``RecursionError``, which ``guard/cli.py``'s top-level
  ``except Exception: defer(...)`` in ``main()`` already catches -- the
  correct fail-safe outcome via the existing catch-all, no bespoke depth
  limit added here.
"""

from . import quoting

# Contains only [A-Za-z_] -- none of shlex's punctuation_chars (";()<>|&"),
# so it always lexes as one ordinary word wherever it lands (mid-word,
# inside "...", standalone). Same collision-avoidance idea as
# parser._ESCAPED_SEMI, applied to a different sentinel.
PLACEHOLDER = "__BASHGUARD_SUBST__"


def desubstitute(cmd):
    """Replace every read-only ``$(...)``/backtick span in ``cmd`` with
    ``PLACEHOLDER``.

    Returns the rewritten string, or ``None`` if any span is unterminated or
    its inner command isn't provably read-only -- the caller
    (``parser.to_segments``) must then return ``None`` too.
    """
    out = []
    i, n = 0, len(cmd)
    in_double = False
    while i < n:
        c = cmd[i]

        if c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            continue

        if not in_double and c == "$" and cmd[i + 1:i + 2] == "'":
            end = quoting.skip_ansi_c(cmd, i + 1)
            if end is None:
                return None
            out.append(cmd[i:end])
            i = end
            continue

        if not in_double and c == "'":
            end = quoting.skip_single(cmd, i)
            if end is None:
                return None
            out.append(cmd[i:end])
            i = end
            continue

        if c == '"':
            in_double = not in_double
            out.append(c)
            i += 1
            continue

        if c == "$" and cmd[i + 1:i + 2] == "(":
            end = _find_paren_end(cmd, i + 2)
            if end is None or not _inner_is_read_only(cmd[i + 2:end - 1]):
                return None
            out.append(PLACEHOLDER)
            i = end
            continue

        if c == "`":
            end = _find_backtick_end(cmd, i + 1)
            if end is None or not _inner_is_read_only(cmd[i + 1:end - 1]):
                return None
            out.append(PLACEHOLDER)
            i = end
            continue

        out.append(c)
        i += 1

    return "".join(out)


def _find_paren_end(cmd, i):
    """Index just past the ``)`` matching an already-consumed ``$(``.

    ``cmd[i]`` is the first character of the substitution's body; depth
    starts at 1 (the opening paren is already counted). Quoted regions are
    skipped atomically via the shared ``quoting`` primitives, so any parens
    inside them never affect depth -- this also handles a nested
    ``$(...)`` for free, since its own ``(``/``)`` characters are just more
    depth to the same counter, exactly how bash's own parser finds the
    match. Reaching end of string first -> ``None`` (unterminated).
    """
    n = len(cmd)
    depth = 1
    while i < n:
        c = cmd[i]
        if c == "\\":
            i += 2
            continue
        if c == "$" and cmd[i + 1:i + 2] == "'":
            end = quoting.skip_ansi_c(cmd, i + 1)
            if end is None:
                return None
            i = end
            continue
        if c == "'":
            end = quoting.skip_single(cmd, i)
            if end is None:
                return None
            i = end
            continue
        if c == '"':
            end = quoting.skip_double(cmd, i)
            if end is None:
                return None
            i = end
            continue
        if c == "(":
            depth += 1
            i += 1
            continue
        if c == ")":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        i += 1
    return None


def _find_backtick_end(cmd, i):
    """Index just past the next unescaped backtick starting at ``cmd[i]``.

    Deliberately does NOT track nested quoting inside the span -- backticks
    don't nest, and real bash's own backtick-quoting rules are themselves a
    known wart (exactly why ``$(...)`` replaced them). See module docstring
    for why misreading a nested-quote backtick as the terminator fails safe.
    """
    n = len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i + 1
        i += 1
    return None


def _inner_is_read_only(inner):
    # Lazy import: guard/cli.py imports guard/parser.py (which imports this
    # module) at load time, so a top-level `from .cli import evaluate` here
    # would hit a partially-initialized `cli` module. By the time this
    # function actually runs (per-request, from inside to_segments), cli.py
    # has long finished executing. Same pattern as classifiers/find.py and
    # classifiers/xargs.py lazily importing ..registry.
    from .cli import evaluate

    ok, _reason = evaluate(inner)
    return ok
