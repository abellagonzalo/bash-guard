#!/usr/bin/env python3
"""Unit tests for guard/classifiers/git.py.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising ``classify(tokens) -> (ok, reason)`` directly. Faster, and a
failure points straight at this module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly
what the orchestrator passes in. Stdlib-only, like the sibling suites.

    python3 tests/classifiers/test_git.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guard.classifiers import git  # noqa: E402

# (label, tokens, expected_ok) -- pure reads + conditional subcommands.
CASES = [
    ("git status", ["git", "status"], True),
    ("git merge-base", ["git", "merge-base", "HEAD", "main"], True),
    ("git commit", ["git", "commit", "-m", "x"], False),
    ("git config --get", ["git", "config", "--get", "user.name"], True),
    ("git config --list", ["git", "config", "--list"], True),
    ("git config set", ["git", "config", "user.name", "bob"], False),
    ("git config --unset", ["git", "config", "--unset", "foo"], False),
    ("git tag bare", ["git", "tag"], True),
    ("git tag -l", ["git", "tag", "-l", "v*"], True),
    ("git tag create", ["git", "tag", "v1.0"], False),
    ("git tag -d", ["git", "tag", "-d", "v1.0"], False),
    ("git stash list", ["git", "stash", "list"], True),
    ("git stash bare", ["git", "stash"], False),
    ("git worktree list", ["git", "worktree", "list"], True),
    ("git worktree add", ["git", "worktree", "add", "../x"], False),
    ("git submodule status", ["git", "submodule", "status"], True),
    ("git submodule update", ["git", "submodule", "update"], False),
    ("git -C distrust", ["git", "-C", "/x", "status"], False),
    ("git bare", ["git"], False),
    ("git --version", ["git", "--version"], True),
    ("git --help", ["git", "--help"], True),
    ("git -h", ["git", "-h"], True),
    ("git version", ["git", "version"], True),
    ("git help", ["git", "help"], True),
    ("git -C distrust before --version", ["git", "-C", "/x", "--version"], False),
    # issue #17: an unrecognized value-taking global flag must not be misread
    # as boolean-and-skip -- the real (mutating) subcommand after it must
    # still be inspected, not hidden as harmless trailing args.
    ("git --git-dir value misread as subcommand",
     ["git", "--git-dir", "status", "commit", "-m", "x"], False),
    ("git --work-tree value misread as subcommand",
     ["git", "--work-tree", "log", "push"], False),
]


def main() -> int:
    failures = []
    for label, tokens, expected in CASES:
        ok, _reason = git.classify(tokens)
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
