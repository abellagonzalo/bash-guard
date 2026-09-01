"""docker: pure-read subcommands + read-only forms of context/compose.

Widen pure reads by editing ``DOCKER_READ``. ``context`` and ``compose`` are
read-only only in certain forms and get explicit branches below.
"""

from .base import ALLOW, deny

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


def classify(tokens):
    # First bare word after global flags is the subcommand.
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        if tokens[i] in DOCKER_INTROSPECT:
            # Pure introspection (prints and exits) -> read-only.
            return ALLOW
        # Unrecognized global flag (e.g. -H, --context) -> skip rather than
        # trust; worst case the eventual subcommand lookup misses and we
        # defer, never a false allow.
        i += 1
    if i >= len(tokens):
        return deny("bare docker (no subcommand)")
    sub = tokens[i]
    args = tokens[i + 1:]
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
