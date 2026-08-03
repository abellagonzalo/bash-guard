"""date: read-only unless it sets the system clock."""

from .base import ALLOW, deny

NAMES = ("date",)


def classify(tokens):
    # `date -s/--set` sets the system clock; everything else just reads.
    for t in tokens[1:]:
        if t == "-s" or t == "--set" or t.startswith("--set="):
            return deny("date sets the system clock")
    return ALLOW
