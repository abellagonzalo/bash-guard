"""env: read-only only when it doesn't run a command."""

from .base import ALLOW, deny

NAMES = ("env",)


def classify(tokens):
    # `env` alone / with only NAME=VALUE assignments just prints or sets env
    # for... nothing. Any bare operand is a command it would RUN.
    for t in tokens[1:]:
        if t.startswith("-"):
            if t == "-0":
                continue
            return deny("env with options we don't auto-trust")
        if "=" in t:
            continue
        return deny("env runs a command")
    return ALLOW
