#!/usr/bin/env python3
"""
Regression tests for bash-guard.py.

Runs the hook end-to-end (feeding a PreToolUse JSON payload on stdin, exactly as
Claude Code does) and asserts each command is either "allow"-ed or deferred.

    python3 test_bash_guard.py     # -> prints a summary, exits 1 on any failure

Safety reminder: the hook may ONLY "allow" (provably read-only) or defer. It
never emits ask/deny. So the only failure that matters for safety is a mutating
command that gets "allow"-ed; the ALLOW list below guards convenience, the DEFER
list guards safety.
"""

import json
import subprocess
import sys
from pathlib import Path

HOOK = str(Path(__file__).with_name("bash-guard.py"))

# Commands that MUST be auto-approved (provably read-only).
ALLOW = [
    "cat file.txt",
    "git log | grep FIX",
    "ls -la /tmp",
    "find . -name '*.py'",
    "sed -n '1,5p' f",
    "awk '{print $1}' f",
    "grep x f 2>/dev/null",
    "sort f > /dev/null",
    "head -n 5 f 2>/dev/null",
    "wc -l < file",
    "printf 'x' | base64",
    "df -h",
    "uname -a",
    "test -f /etc/hosts",
    "git config --get user.name",
    "git config --list",
    "git tag",
    "git tag -l 'v*'",
    "git stash list",
    "git worktree list",
    "git submodule status",
    "git merge-base HEAD main",
    "git --version",
    "git --help",
    "gh pr view 123",
    "gh pr list",
    "gh auth status",
    "gh gist list",
    "gh api repos/foo/bar",
    "curl https://example.com",           # curl defaults to GET -> read-only
    "curl -fsSL https://example.com",
    "curl -o /tmp/x https://example.com | grep foo",  # output confined to /tmp
    "cat a | sort | uniq -c | sort -rn",
    # cd / dir-stack navigation is read-only; the joined command is still vetted.
    "cd src && grep foo bar",
    "pushd /tmp",
    # Leading `VAR=value` assignments are stripped before classifying.
    "FOO=bar grep x y",
    "FOO=bar",
    # sort/yq read forms stay auto-approved.
    "sort -rn f",
    "yq '.a' f",
    "grep x f 2>&1",            # fd duplication -> harmless
    "grep x f 2>&1 | sort",
    "sort f >&2",               # stdout to stderr fd -> harmless
    "cat f 2>/dev/null >&2",
    # Writes confined to a temp dir -> auto-approved.
    "echo hi > /tmp/f",
    "cat a >> /tmp/log",
    "cat f 2>/tmp/err",
    "touch /tmp/x",
    "mkdir -p /tmp/a/b",
    "cat f | tee /tmp/log",
    "cp src.txt /tmp/dst",       # cp source may live outside /tmp
    "mv /tmp/a /tmp/b",
    "rm -rf /tmp/x",
    "echo x > $TMPDIR/f",
    "touch /private/tmp/x",
    # xargs pipelines wrapping a pure read -> auto-approved (mirrors real log).
    "find . -name '*.py' | xargs grep -l foo",
    "find . -name '*.kt' | xargs grep -l x 2>/dev/null | head -20",
    "find . -type f | xargs -0 cat",
]

# Commands that MUST defer (mutating, unknown, or unprovable). A failure here is
# a SAFETY failure.
DEFER = [
    "git commit -m x",
    "git tag v1.0",
    "git config user.name bob",
    "git config --unset foo",
    "git stash",
    "git worktree add ../x",
    "git submodule update",
    "sed -i s/a/b/ f",
    "sed --in-place s/a/b/ f",
    "find . -delete",
    "find . -name a#b -delete",  # commenters-disabled: -delete must be seen
    "awk '{system(\"rm x\")}' f",
    "echo hi > out.txt",
    "cat f | tee out.txt",
    "grep x f 2>err.log",
    "env FOO=1 bash",
    "command rm x",
    "date -s '2020-01-01'",
    "gh pr create",
    "gh pr merge 1",
    "gh api -X POST repos/foo/bar",
    "gh api repos/foo -f name=x",
    "curl -X POST https://example.com",   # non-GET verb -> defer
    "curl -o out.txt https://example.com",  # writes outside a temp dir
    "sort -o out.txt f",         # -o writes a file (was a false-allow)
    "sort -o /etc/passwd f",     # -o writes an arbitrary file
    "yq -i '.a=1' config.yaml",  # in-place edit (was a false-allow)
    "yq --inplace '.a=1' config.yaml",
    "totallyunknowncmd --flag",
    "echo $(rm x)",
    "( rm x )",
    "grep x f >&out.log",       # &-redirect to a FILE -> a write (was false-allow)
    "echo hi &>out.log",        # both streams to a file -> a write
    "cat f &>>log.txt",         # append both streams to a file -> a write
    "cat f 1>2",                # `>` numeric target is a file named "2" -> write
    "cat f <>rw.txt",           # `<>` opens the file for read+write -> a write
    # Temp-write guard rejects anything not confined to a temp dir.
    "echo hi > /tmpfoo",        # prefix trap: /tmpfoo is NOT under /tmp
    "touch /etc/x",
    "cp /etc/hosts ~/h",        # cp destination outside a temp dir
    "mv /tmp/a /etc/b",         # mv destination outside a temp dir
    "cp -t /etc src /tmp/x",    # target-directory flag redirects the real dest
    "echo x > /tmp/../etc/passwd",  # traversal escapes /tmp
    "rm /etc/x",
    # xargs must defer when the wrapped command isn't an operand-independent read.
    "find / -name '*.log' | xargs rm",   # deletes injected, unseen paths
    "find . -type f | xargs sed -i s/a/b/",  # in-place edit
]


def run(command: str) -> str:
    """Return the hook's permissionDecision, or "defer" when it emits nothing."""
    payload = json.dumps({"tool_input": {"command": command}})
    proc = subprocess.run(
        [sys.executable, HOOK],
        input=payload,
        capture_output=True,
        text=True,
    )
    out = proc.stdout.strip()
    if not out:
        return "defer"
    try:
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    except Exception:
        return f"BAD_OUTPUT:{out!r}"


def main() -> int:
    failures = []
    for c in ALLOW:
        got = run(c)
        status = "ok" if got == "allow" else "FAIL"
        if got != "allow":
            failures.append(("ALLOW", c, got))
        print(f"[{status}] allow  <- {c!r} (got {got})")
    for c in DEFER:
        got = run(c)
        status = "ok" if got == "defer" else "FAIL"
        if got != "defer":
            failures.append(("DEFER", c, got))
        print(f"[{status}] defer  <- {c!r} (got {got})")

    print()
    total = len(ALLOW) + len(DEFER)
    if failures:
        print(f"{len(failures)}/{total} FAILED:")
        for kind, c, got in failures:
            print(f"  expected {kind.lower()} but got {got!r}: {c!r}")
        return 1
    print(f"All {total} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
