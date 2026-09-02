"""docker: pure-read subcommands + read-only forms of context/compose.

Widen pure reads by editing ``DOCKER_READ``. ``context`` and ``compose`` are
read-only only in certain forms and get explicit branches below.
"""

from typing import List

from .base import ALLOW, Result, deny
from .subcommand import find_subcommand

NAMES = ("docker",)

# docker subcommands that only read.
DOCKER_READ = {
    "ps", "images", "info", "inspect", "logs", "version", "top", "stats",
    "diff",
}

# docker compose subcommands that only read.
COMPOSE_READ = {"ps", "logs", "config", "images", "ls", "top", "port", "version"}

# Top-level introspection flags: print info and exit, never mutate.
DOCKER_INTROSPECT = {"--version", "-v", "--help"}


def classify(tokens: List[str]) -> Result:
    # An introspection flag (prints and exits) always wins if it's the very
    # first token. Any OTHER leading flag -- e.g. -H/--context, which take a
    # separate value -- must not be skipped past unrecognized: the value
    # would be misread as the subcommand, hiding the real one. find_subcommand()
    # fails safe on those instead of guessing.
    if len(tokens) > 1 and tokens[1] in DOCKER_INTROSPECT:
        return ALLOW
    sub, args = find_subcommand(tokens)
    if sub is None:
        return deny("docker with no confirmed subcommand (bare, or an unrecognized/untrusted global flag)")
    if sub in DOCKER_READ:
        return ALLOW
    if sub == "context":
        if args and args[0] in ("ls", "list", "show", "inspect"):
            return ALLOW
        return deny("docker context (only ls/list/show/inspect read)")
    if sub == "compose":
        if args and args[0] in COMPOSE_READ:
            return ALLOW
        return deny("docker compose (only ps/logs/config/images/ls/top/port/version read)")
    return deny("docker subcommand not in read-only set")
