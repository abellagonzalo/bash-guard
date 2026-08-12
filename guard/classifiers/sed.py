"""sed: read-only unless it edits in place, writes a file, or executes.

Beyond in-place editing (``-i``), a sed *script* can also mutate:
  * ``w FILE`` / ``W FILE``        write the pattern space to a file
  * ``s/re/repl/w FILE``           substitution write flag
  * ``e`` / ``e CMD`` / ``s///e``  GNU sed: execute a shell command

We scan the script for these constructs and defer if any is present. sed scripts
cannot be parsed perfectly (arbitrary delimiters, escaping), so the matching is
conservative and FAIL SAFE: it errs toward deferring, which may cause some
legitimate scripts (e.g. a replacement text that contains ``w <space>``) to
prompt instead of auto-approving. A script supplied via ``-f FILE`` can't be
inspected at all, so that form always defers.
"""

import re

from .base import ALLOW, deny

NAMES = ("sed",)

# APPEND-SAFE (non `-i` forms): only inspects flags and script text, never
# operand POSITION, so appending more trailing operands (as `xargs`/
# `find -exec ... {} +` do) can't turn an ALLOW into something unsafe. See
# guard/registry.py.
APPEND_SAFE = True

# A command boundary: script start, a separator, or the tail of an address
# (line number, `$`, `/regex/`, range comma). The write/exec commands are only
# real commands when they sit at such a boundary.
_BOUNDARY = r"(?:^|[;{}\s/$0-9,])"

# `w FILE` / `W FILE` write command (a filename must follow after whitespace).
# Also catches the substitution write flag `s/re/repl/w FILE` (the `w` sits
# right after the closing `/`, which is a boundary char).
_WRITE_CMD = re.compile(_BOUNDARY + r"[wW][ \t]")

# `e` (execute pattern space), `e CMD`, or the substitution `e` flag
# `s/re/repl/e` (the `e` sits after the closing `/` and ends the command).
_EXEC_CMD = re.compile(_BOUNDARY + r"e(?:[;{}\s]|$)")

# Substitution flag run carrying `w`/`e`/`W` behind other flags, e.g.
# `s/a/b/gw file` or `s|a|b|e`. Common delimiters only; a miss here just defers
# less, and the boundary regexes above still catch the plain forms.
_SUBST_WE_FLAG = re.compile(r"s([/|#,:@]).*?\1.*?\1[0-9gpiImM]*[ewW]", re.S)


def _is_inplace(t):
    return t == "--in-place" or t.startswith("--in-place=") \
        or bool(re.match(r"-[a-zA-Z]*i", t))


def classify(tokens):
    args = tokens[1:]
    scripts = []
    script_seen = False
    have_e = False
    i = 0
    while i < len(args):
        t = args[i]
        if _is_inplace(t):
            return deny("sed in-place edit (-i)")
        if t in ("-f", "--file") or t.startswith("--file="):
            return deny("sed -f reads an un-inspectable script file")
        if t in ("-e", "--expression"):
            have_e = True
            if i + 1 < len(args):
                scripts.append(args[i + 1])
                i += 2
                continue
            i += 1
            continue
        if t.startswith("--expression="):
            have_e = True
            scripts.append(t[len("--expression="):])
            i += 1
            continue
        if t.startswith("-e") and len(t) > 2:  # attached form: -es/a/b/
            have_e = True
            scripts.append(t[2:])
            i += 1
            continue
        if t.startswith("-") and t != "-":
            # Any other option (-n, -r, -E, -s, -z, -u, --posix, ...). Value-
            # taking ones like -l/--line-length carry a harmless numeric arg.
            i += 1
            continue
        # Bare operand: the first one (when no -e was given) is the script;
        # the rest are input files, which we don't scan.
        if not have_e and not script_seen:
            scripts.append(t)
            script_seen = True
        i += 1

    for s in scripts:
        if _WRITE_CMD.search(s) or _EXEC_CMD.search(s) or _SUBST_WE_FLAG.search(s):
            return deny("sed script writes a file or executes a command (w/W/e)")
    return ALLOW
