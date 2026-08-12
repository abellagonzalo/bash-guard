"""Pure read-only utilities: safe as any pipeline stage with no arg inspection.

To add a pure read utility, append it to ``NAMES``. If a command is read-only
only in *some* forms, give it a dedicated module instead.
"""

from .base import ALLOW

# APPEND-SAFE: ignores all arguments, so appending more trailing operands (as
# `xargs`/`find -exec ... {} +` do) can never change an ALLOW verdict. See
# guard/registry.py.
APPEND_SAFE = True

NAMES = (
    "cat", "tac", "nl", "head", "tail", "rev", "cut", "tr", "uniq",
    "comm", "join", "paste", "fold", "expand", "unexpand", "column", "wc",
    "grep", "egrep", "fgrep", "rg", "ag", "jq", "od", "xxd", "hexdump",
    "strings", "base64", "echo", "printf", "seq", "pwd", "whoami",
    "id", "printenv", "ls", "stat", "file", "dirname", "basename",
    "realpath", "readlink", "diff", "cmp", "true", "false", "sha256sum",
    "md5sum", "shasum", "cksum", "tree", "which", "ps",
    # Directory navigation: changes the shell's cwd / dir stack only, never
    # touches the filesystem. (`sort`/`yq` are NOT here — they can write via a
    # flag; see classifiers/sort.py and classifiers/yq.py.)
    "cd", "pushd", "popd", "dirs",
    # System info / no-op predicates: read-only, no filesystem or state changes.
    "uname", "hostname", "uptime", "arch", "nproc", "tty", "groups", "type",
    "test", "[", "getconf", "locale", "df", "du", "free", "sleep",
)


def classify(tokens):
    return ALLOW
