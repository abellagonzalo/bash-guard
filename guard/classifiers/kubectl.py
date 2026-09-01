"""kubectl: read-only verbs + read-only forms of config.

Widen reads by editing ``KUBECTL_READ``. ``config`` is read-only only in
certain forms and gets an explicit branch below.
"""

from .base import ALLOW, deny

NAMES = ("kubectl",)

# kubectl subcommands that only read.
KUBECTL_READ = {
    "get", "describe", "logs", "version", "explain", "top",
    "api-resources", "api-versions",
}

# Global flags that select context/connection and take a separate value
# token -> safe to skip both without affecting the subcommand lookup.
KUBECTL_VALUE_FLAGS = {"-n", "--namespace", "--context", "--cluster", "--kubeconfig"}


def classify(tokens):
    # First bare word after global flags is the subcommand.
    rest = tokens[1:]
    i, sub = 0, None
    while i < len(rest):
        t = rest[i]
        if t in KUBECTL_VALUE_FLAGS:
            i += 2
            continue
        if t.startswith("-"):
            # Unrecognized global flag -> skip rather than trust; worst case
            # the eventual subcommand lookup misses and we defer, never a
            # false allow.
            i += 1
            continue
        sub = t
        i += 1
        break
    if sub is None:
        return deny("bare kubectl (no subcommand)")
    args = rest[i:]
    if sub in KUBECTL_READ:
        return ALLOW
    if sub == "config":
        if args and args[0] in (
            "current-context", "view", "get-contexts", "get-clusters", "get-users",
        ):
            return ALLOW
        return deny("kubectl config (only current-context/view/get-* read)")
    return deny("kubectl subcommand not in read-only set")
