"""command: `command -v/-V NAME` looks up; `command NAME ...` RUNS NAME.

The lookup flag only means "look up" when it LEADS the arguments. Searching for
``-v``/``-V`` anywhere (e.g. ``command bash -v -c '...'``) matches a flag that
belongs to the command being RUN, so we anchor it to the first argument (after
an optional POSIX ``-p``). Anything else runs its argument -> defer.
"""

from .base import ALLOW, deny

NAMES = ("command",)


def classify(tokens):
    args = tokens[1:]
    i = 1 if args and args[0] == "-p" else 0
    if i < len(args) and args[i] in ("-v", "-V"):
        return ALLOW
    return deny("command runs its argument")
