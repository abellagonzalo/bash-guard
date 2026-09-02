"""kubectl: read-only verbs + read-only forms of config.

Widen reads by editing ``KUBECTL_READ``. ``config`` is read-only only in
certain forms and gets an explicit branch below.
"""

from typing import List

from .base import ALLOW, Result, deny
from .subcommand import find_subcommand

NAMES = ("kubectl",)

# kubectl subcommands that only read.
KUBECTL_READ = {
    "get", "describe", "logs", "version", "explain", "top",
    "api-resources", "api-versions",
}

# Global flags that select context/connection/identity and take a separate
# value token -> safe to skip both without affecting the subcommand lookup.
# Not exhaustive of every real kubectl global flag: an unrecognized one still
# fails safe via find_subcommand() rather than being guessed as boolean.
KUBECTL_VALUE_FLAGS = {
    "-n", "--namespace", "--context", "--cluster", "--kubeconfig",
    "--as", "--as-group", "--token", "--server", "--user",
    "--client-certificate", "--client-key", "--certificate-authority",
    "--cache-dir",
}


def classify(tokens: List[str]) -> Result:
    sub, args = find_subcommand(tokens, value_flags=KUBECTL_VALUE_FLAGS)
    if sub is None:
        return deny("kubectl with no confirmed subcommand (bare, or an unrecognized/untrusted global flag)")
    if sub in KUBECTL_READ:
        return ALLOW
    if sub == "config":
        if args and args[0] in (
            "current-context", "view", "get-contexts", "get-clusters", "get-users",
        ):
            return ALLOW
        return deny("kubectl config (only current-context/view/get-* read)")
    return deny("kubectl subcommand not in read-only set")
