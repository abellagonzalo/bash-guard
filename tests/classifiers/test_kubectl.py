#!/usr/bin/env python3
"""Unit tests for guard/classifiers/kubectl.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_kubectl.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import kubectl  # noqa: E402

# (label, tokens, expected_ok) -- read verbs + conditional config.
CASES = [
    ("kubectl get", ["kubectl", "get", "pods"], True),
    ("kubectl -n get", ["kubectl", "-n", "ns", "get", "svc"], True),
    ("kubectl describe", ["kubectl", "describe", "pod", "x"], True),
    ("kubectl config current-context",
     ["kubectl", "config", "current-context"], True),
    ("kubectl config view", ["kubectl", "config", "view"], True),
    ("kubectl config set",
     ["kubectl", "config", "set-context", "x"], False),
    ("kubectl delete", ["kubectl", "delete", "pod", "x"], False),
    ("kubectl apply", ["kubectl", "apply", "-f", "x.yaml"], False),
    ("kubectl bare", ["kubectl"], False),
    ("kubectl namespace only bare", ["kubectl", "-n", "ns"], False),
    # issue #17: --as takes a separate value (impersonated user); the old
    # unrecognized-flags-are-boolean loop misread that value as the
    # subcommand and hid the real, mutating "delete" after it.
    ("kubectl --as value misread as subcommand",
     ["kubectl", "--as", "get", "delete", "pod", "x"], False),
    ("kubectl --as with real read subcommand",
     ["kubectl", "--as", "bob", "get", "pods"], True),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = kubectl.classify(tokens)
        status = "ok" if ok == expected else "FAIL"
        if ok != expected:
            failures.append((label, tokens, ok, expected))
        print(f"[{status}] {label}: got ok={ok}, want {expected}")

    print()
    if failures:
        print(f"{len(failures)}/{len(CASES)} FAILED:")
        for label, tokens, got, want in failures:
            print(f"  {label}: got {got!r}, want {want!r} (tokens={tokens})")
        return 1
    print(f"All {len(CASES)} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
