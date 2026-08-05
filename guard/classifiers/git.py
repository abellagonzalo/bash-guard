"""git: pure-read subcommands + read-only forms of config/tag/stash/etc.

Widen pure reads by editing ``GIT_READ``. Subcommands that read only in certain
forms (``config``, ``tag``, ``stash``, ``worktree``, ``submodule``) get an
explicit branch below.
"""

from .base import ALLOW, deny

NAMES = ("git",)

# git subcommands that only read. (Note: "tag" is excluded — `git tag <name>`
# creates a tag; only its bare/`-l` form lists, which is handled below.)
GIT_READ = {
    "status", "log", "diff", "show", "branch", "blame", "remote", "rev-parse",
    "ls-files", "ls-tree", "cat-file", "describe", "shortlog", "reflog",
    "whatchanged", "show-ref", "for-each-ref", "rev-list",
    # Pure-read plumbing (never mutates regardless of args).
    "merge-base", "name-rev", "check-ignore", "check-attr", "count-objects",
    "grep", "cherry", "var",
    # Introspection subcommands: print info and exit, never mutate.
    "version", "help",
}

# Top-level introspection flags: print info and exit, never mutate.
GIT_INTROSPECT = {"--version", "--help", "-h"}


def classify(tokens):
    # First bare word after global flags is the subcommand.
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        if tokens[i] in GIT_INTROSPECT:
            # Pure introspection (prints and exits) -> read-only.
            return ALLOW
        if tokens[i] == "-c" or tokens[i] == "--exec-path" or tokens[i] == "-C":
            # value-taking / potentially unsafe global flags -> be strict.
            return deny("git with a global flag we don't auto-trust")
        i += 1
    if i >= len(tokens):
        return deny("bare git (no subcommand)")
    sub = tokens[i]
    args = tokens[i + 1:]
    if sub in GIT_READ:
        return ALLOW
    # Subcommands that read only in certain forms -> inspect their args.
    if sub == "config":
        writes = {
            "--add", "--unset", "--unset-all", "--replace-all", "--edit",
            "-e", "--rename-section", "--remove-section",
        }
        reads = {
            "--get", "--get-all", "--get-regexp", "--get-urlmatch",
            "--list", "-l",
        }
        if any(a in writes for a in args):
            return deny("git config write")
        if any(a in reads for a in args):
            return ALLOW
        return deny("git config without an explicit read flag (may set a value)")
    if sub == "tag":
        if any(a in ("-l", "--list") for a in args):
            return ALLOW
        # Bare `git tag` (or only flags like -n) lists; a bare operand names a
        # tag to CREATE, and -d/-a/-s/-m/-f create or delete.
        if all(a.startswith("-") for a in args):
            if any(a in ("-d", "--delete", "-a", "--annotate", "-s",
                         "--sign", "-f", "--force", "-m", "--message")
                   for a in args):
                return deny("git tag create/delete")
            return ALLOW
        return deny("git tag with an operand (creates a tag)")
    if sub == "stash":
        if args and args[0] in ("list", "show"):
            return ALLOW
        return deny("git stash (bare form pushes; only list/show read)")
    if sub == "worktree":
        if args and args[0] == "list":
            return ALLOW
        return deny("git worktree (only list reads)")
    if sub == "submodule":
        if args and args[0] in ("status", "summary"):
            return ALLOW
        return deny("git submodule (only status/summary read)")
    return deny("git subcommand not in read-only set")
