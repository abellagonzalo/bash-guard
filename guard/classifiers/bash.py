"""bash: read-only only for the literal ``bash -c '<script>'`` shape.

The inline script is recursively classified through the same
segment/classifier pipeline as everything else (``guard.cli.evaluate()``),
the same recursion pattern ``guard/substitution.py`` already uses for
``$(...)``/backticks. Any other invocation -- including ``bash <path>``,
which would require reading the script off disk -- is out of scope here and
always defers (see issue #13; the file-read case needs its own trust
decision around a script-path allowlist and TOCTOU, tracked separately).

Recognition is deliberately narrow: only ``-c`` as the very first argument,
with the script as the very next token. Any other flag, ordering, or bundled
short-flag cluster (e.g. ``-lc``) defers rather than being guessed at --
mirroring this codebase's existing bias toward under-recognizing a flag
shape rather than misreading one (see the git/docker/kubectl global-flag
false-allow fixed for issue #17).
"""

from .base import ALLOW, deny

NAMES = ("bash",)

# No APPEND_SAFE: bash isn't registered as append-safe, so wrapping it via
# `find -exec`/`xargs` still defers exactly as before (now via the "isn't
# append-safe" reason instead of "unknown command") -- unchanged behavior,
# see guard/registry.py.


def classify(tokens):
    # Lazy import: same circular-init reason as substitution.py's
    # _inner_is_read_only and find.py/xargs.py's lazy `..registry` import --
    # guard/cli.py imports guard/registry.py (which imports this module) at
    # load time, so a top-level `from ..cli import evaluate` here would hit
    # a partially-initialized `cli` module.
    from ..cli import evaluate

    args = tokens[1:]
    if len(args) < 2 or args[0] != "-c":
        return deny(
            "bash without a literal -c '<script>' as its first argument is "
            "not analyzed"
        )

    script = args[1]
    ok, reason = evaluate(script)
    if not ok:
        return deny(f"bash -c script is not read-only: {reason}")
    return ALLOW
