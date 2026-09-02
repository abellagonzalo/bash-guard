"""xargs: read-only only when it wraps a provably append-safe read-only command.

`xargs` appends the piped-in operands to the END of the wrapped command it
actually runs. A classifier that reasons about operand POSITION can be fooled
by this: the *visible* tokens `xargs rm /tmp/safe` look all-temp-safe, but at
runtime xargs appends the piped filenames after `/tmp/safe`, so the real
invocation is `rm /tmp/safe file1 file2 ...` -> deletes arbitrary paths. See
`classifiers/wrapped.py` for the shared lookup + APPEND_SAFE gate + recurse
this delegates to (also used by `find.py`'s `-exec` payload).

`-I`/`-i`/`-J`/`--replace` (xargs's replace-string flags) are hard-denied
outright rather than analyzed for read-only safety: they substitute a
piped-in value at an ARBITRARY position in the wrapped command, not just
appended at the end, which defeats even append-safe classifiers' static
analysis (a substituted value could resolve to `-i` for `sed` at runtime
while the static token we see is literally `{}`).

`-e`/`-E` (eof-string) are treated as attached-value-only (`-eSTR`); a
separated `-E STR` form isn't special-cased, so `STR` gets mis-scanned as the
wrapped command and fails the wrapped-command lookup -- a safe over-defer,
never a false allow.

Any unrecognized `-`-prefixed xargs flag defers rather than being silently
skipped, since it might be a replace-string variant we didn't anticipate.
"""

from typing import List

from .base import Result, deny
from .wrapped import classify_wrapped

NAMES = ("xargs",)

# No APPEND_SAFE here: xargs is not append-safe itself, so `xargs xargs ...`
# defers for free via the same check applied to any other wrapped command --
# no special-casing needed.

_BOOL_FLAGS = {
    "-0", "--null", "-p", "--interactive", "-t", "--verbose",
    "-x", "--exit", "-r", "--no-run-if-empty", "--show-limits",
    "-o", "--version", "--help",
}
_VALUE_SHORT = set("nPLlsad")  # -n -P -L -l -s -a -d: take a value
_ATTACHED_ONLY_SHORT = set("eE")  # -e/-E: value only ever taken attached here
_VALUE_LONG = {
    "--max-args", "--max-procs", "--max-lines", "--max-chars",
    "--arg-file", "--delimiter",
}

_REPLACE_REASON = (
    "xargs replace-string flag (-I/-i/-J/--replace) can substitute a "
    "piped-in value at an arbitrary position"
)


def _is_replace_flag(t: str) -> bool:
    if t in ("-I", "-J", "-i") or t.startswith("-I") or t.startswith("-J") \
            or t.startswith("-i"):
        return True
    return t == "--replace" or t.startswith("--replace=")


def classify(tokens: List[str]) -> Result:
    args = tokens[1:]
    i, n = 0, len(args)
    wrapped = None
    while i < n:
        t = args[i]

        if t == "--":
            wrapped = args[i + 1:]
            break
        if t == "-" or not t.startswith("-"):
            wrapped = args[i:]
            break

        if _is_replace_flag(t):
            return deny(_REPLACE_REASON)

        if t.startswith("--"):
            name, sep, _val = t.partition("=")
            if name in _BOOL_FLAGS:
                i += 1
                continue
            if name in _VALUE_LONG:
                i += 1 if sep else 2
                continue
            return deny(f"unrecognized xargs flag: {t}")

        if t in _BOOL_FLAGS:
            i += 1
            continue
        letter = t[1]
        if letter in _ATTACHED_ONLY_SHORT:
            i += 1
            continue
        if letter in _VALUE_SHORT:
            i += 1 if len(t) > 2 else 2
            continue
        return deny(f"unrecognized xargs flag: {t}")

    return classify_wrapped(wrapped, context="xargs")
