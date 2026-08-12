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
    # Escaped/quoted parens are literal `find` operands, not subshell grouping.
    'find . -type f \\( -name "*.kt" -o -name "*.yml" \\) | head -50',
    'find . -path ./build -prune -o \\( -name "*.sql" \\) -print | head',
    "find . '(' -name x ')'",
    "grep '(' file",
    'grep "(x)" file',
    r"rg '\(foo\)' src",         # escaped parens inside a regex
    "echo a \\\n && ls",         # backslash-newline continuation
    # A mid-token `#` is an ordinary character to bash, so the comment bail-out
    # is scoped to a WORD START. Without that scoping these become false defers
    # and `find . -name a#b -delete` below stops exercising `commenters = ""`.
    "find . -name a#b",
    "grep -v ^# /etc/hosts",
    "x=abc; echo ${#x}",         # `${#x}` length expansion, not a comment
    "echo hi\\\nx#y",            # continuation joins the lines -> `#` is mid-word
    # A quoted `#` or `<<` never reaches the bail-out: the walk skips quoted
    # regions whole. Both of these are real auto-allowed commands from the log.
    "grep '#' file",
    "sed 's#a/b#c/d#' f",        # `#` as sed's separator
    'grep -n "env run\\|command\\|# env\\|# date" test_classifiers.py | head -30',
    'grep -rn "heredoc\\|<<\\|commenters" --include=*.py --include=*.md .',
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
    # Punctuation runs COLLAPSE into one token, so `;(` is neither a segment
    # separator nor equal to "(" — the old token-list check missed these and
    # auto-allowed them. bash runs the subshell. These are the safety
    # regressions the raw-string scan exists to prevent.
    "echo ;(rm -rf /tmp/x);",
    "echo x ||(rm x)||echo y",
    "cat f |(rm x)",
    "echo x &(rm x)",
    # Real subshell grouping still defers now that the check reads the raw string.
    "(cd /tmp && ls)",              # read-only body, but still grouping
    "echo x && (rm -rf /tmp/x)",    # subshell after an otherwise safe segment
    "echo a\n(rm x)",               # subshell on a second line
    "f() { rm x; }",                # shlex collapses `()` into ONE token
    "echo 'a\\' ( rm x )",          # `\` is not an escape inside '…' -> paren is real
    "grep 'unterminated f",         # unterminated quote -> defer
    'grep "x f',                    # unterminated double quote
    "echo x \\",                    # trailing backslash -> lexer ValueError
    "x=(a b c)",                    # array assignment
    "((i++)) ; ls",                 # arithmetic command
    "case x in a) rm y;; esac",     # `)` as a case pattern terminator
    "echo ${x:-(} ; ls",            # paren from a parameter expansion
    # ANSI-C `$'…'`: bash lets `\` escape inside it, this walk and shlex do not.
    # Two crafted `\'` shift the quote phase and shift it back, so both sides end
    # balanced and the unterminated-quote fail-safe never fires — bash then runs
    # a command we read as the CONTENTS of a string. Verified against real bash;
    # both of these were auto-allowed before `$'` became its own bail-out.
    "echo $'\\''; (touch /tmp/x); echo \\'",   # hides a subshell
    "echo $'\\''; rm -rf /tmp/x; echo \\'",    # ... and needs no paren at all
    "echo $'a\\'b' ; (rm x) ; echo $'c\\'d'",  # one desync -> unterminated quote
    "grep $'\\t' f",            # plain ANSI-C use defers too: 0 hits in the log
    'echo $"hi" && (rm x)',     # `$"…"` quotes like `"…"`; the paren is the defer
    # Comments and heredoc bodies are INERT to bash but ordinary text to this
    # walk and to shlex (`commenters = ""`). An odd quote count inside one such
    # region shifts our quote phase and a second shifts it back, so both sides
    # end balanced, no fail-safe fires, and a later REAL command is read as the
    # contents of a string. Verified against real bash — every one of these runs
    # `printf X` and was auto-allowed before the `#`/`<<` bail-outs.
    "echo hi # don't\nprintf X # it's",
    'echo hi #"\nprintf X #"',
    "cat <<EOF\ndon't\nEOF\nprintf X # it's",
    "cat <<EOF\ndon't\nEOF\nprintf X\ncat <<EOF\nit's\nEOF",   # `<<` alone, no `#`
    # `\` + newline is line continuation: bash deletes the pair, so the char
    # BEFORE the backslash decides the word start and both `#` below are still
    # comments. Clearing word_start on every escape pair misses these.
    "echo hi \\\n# don't\nprintf X \\\n# it's",
    'echo hi \\\n#"\nprintf X \\\n#"',
    # Every word-start position for `#`, and every heredoc/here-string form.
    "# just a comment\nls",     # start of the string
    "ls # trailing",            # after a space
    "ls\t# tab",                # after a tab
    "ls\n# c\nls",              # after a newline
    "ls;# c",
    "ls|# c",
    "cat <<'EOF'\nhi\nEOF",     # quoted heredoc delimiter
    "cat <<-EOF\n\thi\nEOF",    # tab-stripping heredoc
    "grep x <<<'a'",            # here-string: no inert body, deliberate over-bail
    'find . \\( -name "*.kt" \\) -delete',  # literal parens, but find still denies
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
