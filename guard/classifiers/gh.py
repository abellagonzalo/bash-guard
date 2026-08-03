"""gh: read-only subcommands + GET-only `gh api`.

Widen reads by editing ``GH_READ``. ``gh api`` is read-only only without a write
method or a request body.
"""

import re

from .base import ALLOW, deny

NAMES = ("gh",)

# gh command group -> set of read-only actions.
GH_READ = {
    "pr": {"view", "list", "diff", "checks", "status"},
    "run": {"view", "list"},
    "issue": {"view", "list", "status"},
    "repo": {"view", "list"},
    "release": {"view", "list"},
    "workflow": {"view", "list"},
    "label": {"list"},
    "cache": {"list"},
    "search": {"prs", "issues", "repos", "code", "commits"},
    "auth": {"status"},
    "gist": {"list", "view"},
}


def classify(tokens):
    # Find group + action (first two "bare" tokens), skipping known
    # value-taking global flags. Unknown flags just make us defer (safe).
    rest = tokens[1:]
    bare, i = [], 0
    while i < len(rest) and len(bare) < 2:
        t = rest[i]
        if t in ("-R", "--repo"):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        bare.append(t)
        i += 1
    group = bare[0] if bare else None
    action = bare[1] if len(bare) > 1 else None
    if group == "api":
        for t in rest:
            if t in ("-X", "--method"):
                return deny("gh api with an explicit HTTP method")
            if re.match(r"(-X|--method)=(POST|PUT|PATCH|DELETE)", t, re.I):
                return deny("gh api with a write HTTP method")
            if t in ("-f", "-F", "--field", "--raw-field", "--input"):
                return deny("gh api with a request body (implies POST)")
        return ALLOW
    if group in GH_READ and action in GH_READ[group]:
        return ALLOW
    return deny("gh subcommand not in read-only set")
