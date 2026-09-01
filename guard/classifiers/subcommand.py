"""Shared subcommand-detection for global-flags-then-subcommand CLIs.

git/docker/kubectl all share this shape: a run of global flags, then a bare
word that is the actual subcommand. Each classifier used to hand-roll this
walk with its own list of "known" value-taking flags, silently treating any
OTHER flag as boolean-and-skip -- which misreads the VALUE of an unrecognized
value-taking flag as the subcommand, hiding the real (possibly mutating)
subcommand in what looked like harmless trailing args (issue #17). This is
the same "independently-derived walks drift out of sync" bug class
``guard/quoting.py`` documents for quote-tracking, applied to subcommand
detection instead.

``find_subcommand`` fails safe: any ``-``-prefixed token it doesn't recognize
halts the walk and returns ``(None, None)`` rather than guessing whether it
takes a value. Callers must treat that the same as "no subcommand found" --
i.e. defer, never allow.
"""


def find_subcommand(tokens, value_flags=frozenset()):
    """Walk ``tokens[1:]`` past known global flags to find the subcommand.

    ``value_flags`` are global flags that consume a separate value token and
    are skipped over safely (both tokens). Any other ``-``-prefixed token is
    NOT assumed boolean -- it might take a value we don't know about -- so
    the walk stops there and returns ``(None, None)``. Running out of tokens
    with no bare word is the same failure.

    Returns ``(sub, rest)`` on success, else ``(None, None)``.
    """
    i = 1
    n = len(tokens)
    while i < n and tokens[i].startswith("-") and tokens[i] != "-":
        if tokens[i] in value_flags:
            i += 2
            continue
        return None, None
    if i >= n:
        return None, None
    return tokens[i], tokens[i + 1:]
