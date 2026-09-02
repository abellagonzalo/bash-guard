"""Command substitution (``$(...)`` / backtick): allowed iff read-only.

Process substitution (``<(...)``, ``>(...)``) is explicitly OUT OF SCOPE and
stays a hard, unconditional defer -- see the raw-substring check in
``guard/parser.py``, run before this module is ever reached.

Walks the raw command tracking bash's own expansion rules: a ``'...'``/
``$'...'`` span is skipped atomically (never live); a ``"..."`` span toggles
a flag but is still scanned character-by-character, since ``$(...)``/
backtick ARE live inside it. Each span found is recursively evaluated
through ``guard.cli.evaluate()`` -- the same segment/classifier pipeline as
the top-level command -- and, if read-only, replaced with a fixed,
metacharacter-free ``PLACEHOLDER`` before the outer command continues
through the ordinary ``to_segments``/``shlex`` pipeline. An unterminated
span or a non-read-only inner command defers the WHOLE outer command.

Known, accepted limitations (fail closed -> extra defer, never a false
allow):

* Nested quotes INSIDE a backtick span are not tracked (backticks don't
  nest); a misread terminator almost always leaves an unbalanced quote,
  caught by ``parser._needs_raw_bailout``'s unterminated-quote check (or
  ``shlex``'s own ``ValueError``).
* ``$((...))`` arithmetic expansion is not special-cased -- it reads as
  ``$(`` with inner text ``(expr)``, which always defers when that's
  recursively parsed (no classifier understands arithmetic).
* Nested substitution drives real Python recursion (``desubstitute ->
  evaluate -> to_segments -> desubstitute -> ...``); pathologically deep
  nesting could raise ``RecursionError``, caught by ``guard/cli.py``'s
  top-level ``except Exception`` in ``main()`` -- the correct fail-safe
  outcome, no bespoke depth limit added here.

See AGENTS.md "How a command is judged" (the command-substitution and
backtick callouts) for the exploit-avoidance rationale and the
paren-depth-counter/nested-``$((...))``/backtick-nesting details.
"""

from typing import Optional

from . import quoting

# Contains only [A-Za-z_] -- none of shlex's punctuation_chars (";()<>|&"),
# so it always lexes as one ordinary word wherever it lands (mid-word,
# inside "...", standalone). Same collision-avoidance idea as
# parser._ESCAPED_SEMI, applied to a different sentinel.
PLACEHOLDER = "__BASHGUARD_SUBST__"


def desubstitute(cmd: str) -> Optional[str]:
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


def _find_paren_end(cmd: str, i: int) -> Optional[int]:
    """Index just past the ``)`` matching an already-consumed ``$(``.

    ``cmd[i]`` is the first character of the substitution's body; depth
    starts at 1. Quoted regions are skipped atomically via the shared
    ``quoting`` primitives, so parens inside them never affect depth -- a
    nested ``$(...)`` is handled for free, no special-casing needed. Reaching
    end of string first -> ``None`` (unterminated).

    See AGENTS.md "How a command is judged" (command-substitution callout)
    for why this mirrors bash's own paren-depth matching.
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


def _find_backtick_end(cmd: str, i: int) -> Optional[int]:
    """Index just past the next unescaped backtick starting at ``cmd[i]``, or
    ``None`` if unterminated.

    Deliberately not quote-aware inside the span (backticks don't nest); see
    module docstring / AGENTS.md for why a misread terminator still fails
    safe.
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


def _inner_is_read_only(inner: str) -> bool:
    # Lazy import: guard/cli.py imports guard/parser.py (which imports this
    # module) at load time, so a top-level `from .cli import evaluate` here
    # would hit a partially-initialized `cli` module. By the time this
    # function actually runs (per-request, from inside to_segments), cli.py
    # has long finished executing. Same pattern as classifiers/find.py and
    # classifiers/xargs.py lazily importing ..registry.
    from .cli import evaluate

    ok, _reason = evaluate(inner)
    return ok
