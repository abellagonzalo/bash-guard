"""bash: read-only only for ``bash -c '<script>'`` or a trusted script path.

Both forms recurse the script text through the same segment/classifier
pipeline as everything else (``guard.cli.evaluate()``), the same recursion
pattern ``guard/substitution.py`` already uses for ``$(...)``/backticks.

``bash <path> [args...]`` (closes #26, a follow-up to #13) reads the script
off disk and recurses into it exactly like ``-c``'s inline text, but only
when ``<path>`` resolves (via ``os.path.realpath``, following symlinks) to a
real file under a trusted root (``_TRUSTED_SCRIPT_ROOTS``, currently
``~/.claude``). This is the only place in ``guard/`` that touches the
filesystem or resolves a path -- every other classifier reasons about
literal shlex tokens only (see ``guard/paths.py``'s "never expand/stat/
resolve" module docstring). Two accepted tradeoffs, decided explicitly
before implementing:

- **TOCTOU**: the file is read once at check time, with no re-check
  immediately before ``bash`` actually executes it. Accepted for this
  local, single-user dev-machine hook -- the same trust model ``-c``
  already applies to its literal script text.
- **Trust scope**: any regular file resolving under ``~/.claude/``, not
  narrowed to a specific subpath or extension.

Script files conventionally start with a ``#!/usr/bin/env bash`` shebang;
``guard/parser.py``'s word-start-``#`` bailout (issue #8) would otherwise
defer every such script outright, so exactly one leading shebang line is
stripped before recursing (mirrors ``_strip_quoted_heredocs`` running before
other passes, for the same "bash-inert but live to us" reason). Any other
``#`` comment in the script still defers -- accepted, fail-safe.

Recognition is deliberately narrow: only ``-c '<script>'`` or a bare
non-flag path as the very first argument. Any other flag, ordering, or
bundled short-flag cluster (e.g. ``-lc``) defers rather than being guessed
at -- mirroring this codebase's existing bias toward under-recognizing a
flag shape rather than misreading one (see the git/docker/kubectl
global-flag false-allow fixed for issue #17). Trailing tokens after the
script path are never inspected -- same opaque-positional-arg treatment
``-c`` already gives its trailing operands.
"""

import os
import re
from typing import List, Optional

from .base import ALLOW, Result, deny

NAMES = ("bash",)

# No APPEND_SAFE: bash isn't registered as append-safe, so wrapping it via
# `find -exec`/`xargs` still defers exactly as before (now via the "isn't
# append-safe" reason instead of "unknown command") -- unchanged behavior,
# see guard/registry.py.

_TRUSTED_SCRIPT_ROOTS = (os.path.expanduser("~/.claude"),)

_SHEBANG_RE = re.compile(r"\A#![^\n]*\n?")


def _read_trusted_script(token: Optional[str]) -> Optional[str]:
    """Return the script's text if token names a real file resolving under a
    trusted root, else None. Fail safe: any ambiguity (relative path,
    missing file, symlink escape, decode error) returns None so the caller
    defers.
    """
    if not token or not (token.startswith("/") or token.startswith("~")):
        return None  # relative paths are CWD-dependent; require absolute/home-anchored

    expanded = os.path.expanduser(token)
    if not os.path.isabs(expanded):
        return None

    try:
        real = os.path.realpath(expanded)
    except OSError:
        return None

    trusted_roots = tuple(os.path.realpath(r) for r in _TRUSTED_SCRIPT_ROOTS)
    if not any(real == root or real.startswith(root + os.sep) for root in trusted_roots):
        return None
    if not os.path.isfile(real):
        return None

    try:
        with open(real, "r", encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _strip_shebang(text: str) -> str:
    return _SHEBANG_RE.sub("", text, count=1)


def classify(tokens: List[str]) -> Result:
    # Lazy import: same circular-init reason as substitution.py's
    # _inner_is_read_only and find.py/xargs.py's lazy `..registry` import --
    # guard/cli.py imports guard/registry.py (which imports this module) at
    # load time, so a top-level `from ..cli import evaluate` here would hit
    # a partially-initialized `cli` module.
    from ..cli import evaluate

    args = tokens[1:]
    if len(args) >= 2 and args[0] == "-c":
        script = args[1]
        ok, reason = evaluate(script)
        if not ok:
            return deny(f"bash -c script is not read-only: {reason}")
        return ALLOW

    if args and not args[0].startswith("-"):
        script_text = _read_trusted_script(args[0])
        if script_text is None:
            return deny(
                f"bash <path> outside a trusted root or unreadable: {args[0]}"
            )
        ok, reason = evaluate(_strip_shebang(script_text))
        if not ok:
            return deny(f"bash script is not read-only: {reason}")
        return ALLOW

    return deny(
        "bash without a literal -c '<script>' or a trusted script path as "
        "its first argument is not analyzed"
    )
