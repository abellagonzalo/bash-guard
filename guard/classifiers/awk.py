"""awk: read-only unless the program shells out or writes files.

Dangerous constructs we defer on:
  * ``system(...)``          -> runs a shell command (space-tolerant match).
  * ``getline``              -> reads a command's output / a file.
  * ``print[f] > file``      -> writes a file.
  * ``print[f] | "cmd"``     -> pipes output to a command (executes it). We match
    a lone ``|`` (or gawk's ``|&`` coprocess) before a string literal, while
    NOT matching the logical-OR operator ``||`` (a common, harmless construct).
"""

import re

from .base import ALLOW, deny

NAMES = ("awk",)

# A pipe into a command string: `print ... | "cmd"` or gawk `|& "cmd"`.
# The lookaround excludes `||` (logical OR) so legit programs aren't deferred.
_PIPE_TO_CMD = re.compile(r'(?<!\|)\|&?\s*"')


def classify(tokens):
    for t in tokens[1:]:
        if (re.search(r"\bsystem\s*\(", t) or "getline" in t
                or re.search(r"print[f]?\s*>", t) or _PIPE_TO_CMD.search(t)):
            return deny("awk program uses system()/getline/pipe/file output")
    return ALLOW
