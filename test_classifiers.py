#!/usr/bin/env python3
"""Unit tests for the individual classifiers.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising each ``classify(tokens) -> (ok, reason)`` function directly. Faster,
and a failure points straight at the offending command's module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly what
the orchestrator passes in. Stdlib-only, like the sibling suite.

    python3 test_classifiers.py     # -> prints a summary, exits 1 on any failure
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from guard.classifiers import (  # noqa: E402
    awk, command, curl, date, env, find, gh, git, readonly, sed, sort, tmpwrite,
    xargs, yq,
)
from guard.registry import CLASSIFIERS  # noqa: E402

# (label, classifier, tokens, expected_ok)
CASES = [
    # readonly — always read-only, no arg inspection.
    ("readonly cat", readonly, ["cat", "x"], True),
    ("readonly grep", readonly, ["grep", "-r", "foo", "."], True),
    ("readonly cd", readonly, ["cd", "/tmp"], True),
    ("readonly pushd", readonly, ["pushd", "/x"], True),

    # sort — writes to a file via -o/--output.
    ("sort read", sort, ["sort", "-rn", "f"], True),
    ("sort -o sep", sort, ["sort", "-o", "out", "f"], False),
    ("sort -o attached", sort, ["sort", "-ofile", "f"], False),
    ("sort --output=", sort, ["sort", "--output=out", "f"], False),
    ("sort bundled o", sort, ["sort", "-rno", "file", "f"], False),

    # yq — edits in place via -i/--inplace; -o is an output FORMAT (harmless).
    ("yq read", yq, ["yq", ".a", "f"], True),
    ("yq output fmt", yq, ["yq", "-o=json", ".a", "f"], True),
    ("yq -i", yq, ["yq", "-i", ".a=1", "f"], False),
    ("yq --inplace", yq, ["yq", "--inplace", ".a=1", "f"], False),
    ("yq bundled i", yq, ["yq", "-iP", ".a=1", "f"], False),

    # find — mutating/executing actions defer.
    ("find name", find, ["find", ".", "-name", "*.py"], True),
    ("find delete", find, ["find", ".", "-delete"], False),
    ("find exec", find, ["find", ".", "-exec", "rm", "{}", ";"], False),
    ("find fprint", find, ["find", ".", "-fprint", "out"], False),

    # sed — in-place edits defer.
    ("sed print", sed, ["sed", "-n", "1,5p", "f"], True),
    ("sed plain sub", sed, ["sed", "s/a/b/", "f"], True),
    ("sed sub file", sed, ["sed", "s/foo/bar/g", "input.txt"], True),
    ("sed -i", sed, ["sed", "-i", "s/a/b/", "f"], False),
    ("sed --in-place", sed, ["sed", "--in-place", "s/a/b/", "f"], False),
    ("sed --in-place=bak", sed, ["sed", "--in-place=.bak", "s/a/b/", "f"], False),
    ("sed write cmd", sed, ["sed", "w /etc/evil", "f"], False),
    ("sed exec cmd", sed, ["sed", "1e touch /tmp/x", "f"], False),
    ("sed sub write flag", sed, ["sed", "s/a/b/w /etc/x", "f"], False),
    ("sed sub exec flag", sed, ["sed", "s/a/b/e", "f"], False),
    ("sed -e write", sed, ["sed", "-e", "w /etc/x", "f"], False),
    ("sed -f file", sed, ["sed", "-f", "script.sed", "f"], False),

    # awk — shell-out / file output / pipe-to-command defer.
    ("awk print", awk, ["awk", "{print $1}", "f"], True),
    ("awk logical or", awk, ["awk", "$1>0 || $2>0", "f"], True),
    ("awk system", awk, ["awk", '{system("rm x")}', "f"], False),
    ("awk system space", awk, ["awk", '{system ("id")}', "f"], False),
    ("awk getline", awk, ["awk", "{getline}", "f"], False),
    ("awk file-out", awk, ["awk", "{print > \"x\"}", "f"], False),
    ("awk pipe shell", awk, ["awk", 'BEGIN{print "id" | "sh"}'], False),
    ("awk coproc pipe", awk, ["awk", 'BEGIN{print "id" |& "sh"}'], False),

    # gh — read subcommands + GET-only api.
    ("gh pr view", gh, ["gh", "pr", "view", "123"], True),
    ("gh pr list", gh, ["gh", "pr", "list"], True),
    ("gh repo flag", gh, ["gh", "-R", "o/r", "pr", "list"], True),
    ("gh pr create", gh, ["gh", "pr", "create"], False),
    ("gh api get", gh, ["gh", "api", "repos/foo"], True),
    ("gh api POST", gh, ["gh", "api", "-X", "POST", "repos/foo"], False),
    ("gh api field", gh, ["gh", "api", "repos/foo", "-f", "name=x"], False),
    ("gh unknown", gh, ["gh", "secret", "set", "X"], False),

    # curl — GET/HEAD reads + temp-dir output; bodies/uploads/non-temp writes defer.
    ("curl bare get", curl, ["curl", "https://x"], True),
    ("curl -fsSL get", curl, ["curl", "-fsSL", "https://x"], True),
    ("curl -X GET", curl, ["curl", "-X", "GET", "https://x"], True),
    ("curl -XGET", curl, ["curl", "-XGET", "https://x"], True),
    ("curl head", curl, ["curl", "-I", "https://x"], True),
    ("curl header", curl, ["curl", "-H", "X-Foo: bar", "https://x"], True),
    ("curl -o tmp", curl, ["curl", "-o", "/tmp/x", "https://x"], True),
    ("curl -o attached tmp", curl, ["curl", "-o/tmp/x", "https://x"], True),
    ("curl --output=tmp", curl, ["curl", "--output=/tmp/x", "https://x"], True),
    ("curl --output-dir tmp", curl, ["curl", "--output-dir", "/tmp", "https://x"], True),
    ("curl -o etc", curl, ["curl", "-o", "/etc/x", "https://x"], False),
    ("curl -X POST", curl, ["curl", "-X", "POST", "https://x"], False),
    ("curl -XPOST", curl, ["curl", "-XPOST", "https://x"], False),
    ("curl --request=PUT", curl, ["curl", "--request=PUT", "https://x"], False),
    ("curl data", curl, ["curl", "-d", "a=b", "https://x"], False),
    ("curl --data=x", curl, ["curl", "--data=a=b", "https://x"], False),
    ("curl form", curl, ["curl", "-F", "f=@x", "https://x"], False),
    ("curl upload", curl, ["curl", "-T", "f", "https://x"], False),
    ("curl remote-name", curl, ["curl", "-O", "https://x"], False),
    ("curl bundled remote-name", curl, ["curl", "-sO", "https://x"], False),
    ("curl config", curl, ["curl", "-K", "cfg"], False),

    # git — pure reads + conditional subcommands.
    ("git status", git, ["git", "status"], True),
    ("git merge-base", git, ["git", "merge-base", "HEAD", "main"], True),
    ("git commit", git, ["git", "commit", "-m", "x"], False),
    ("git config --get", git, ["git", "config", "--get", "user.name"], True),
    ("git config --list", git, ["git", "config", "--list"], True),
    ("git config set", git, ["git", "config", "user.name", "bob"], False),
    ("git config --unset", git, ["git", "config", "--unset", "foo"], False),
    ("git tag bare", git, ["git", "tag"], True),
    ("git tag -l", git, ["git", "tag", "-l", "v*"], True),
    ("git tag create", git, ["git", "tag", "v1.0"], False),
    ("git tag -d", git, ["git", "tag", "-d", "v1.0"], False),
    ("git stash list", git, ["git", "stash", "list"], True),
    ("git stash bare", git, ["git", "stash"], False),
    ("git worktree list", git, ["git", "worktree", "list"], True),
    ("git worktree add", git, ["git", "worktree", "add", "../x"], False),
    ("git submodule status", git, ["git", "submodule", "status"], True),
    ("git submodule update", git, ["git", "submodule", "update"], False),
    ("git -C distrust", git, ["git", "-C", "/x", "status"], False),
    ("git bare", git, ["git"], False),
    ("git --version", git, ["git", "--version"], True),
    ("git --help", git, ["git", "--help"], True),
    ("git -h", git, ["git", "-h"], True),
    ("git version", git, ["git", "version"], True),
    ("git help", git, ["git", "help"], True),
    ("git -C distrust before --version", git, ["git", "-C", "/x", "--version"], False),

    # env — only prints or assigns; running a command defers.
    ("env bare", env, ["env"], True),
    ("env assign", env, ["env", "FOO=1"], True),
    ("env -0", env, ["env", "-0"], True),
    ("env run", env, ["env", "FOO=1", "bash"], False),
    ("env opt", env, ["env", "-i"], False),

    # command — lookup vs run.
    ("command -v", command, ["command", "-v", "ls"], True),
    ("command -V", command, ["command", "-V", "ls"], True),
    ("command -p -v", command, ["command", "-p", "-v", "ls"], True),
    ("command run", command, ["command", "rm", "x"], False),
    ("command run flag late", command, ["command", "bash", "-v", "-c", "x"], False),

    # date — reading vs setting the clock.
    ("date bare", date, ["date"], True),
    ("date fmt", date, ["date", "+%s"], True),
    ("date -s", date, ["date", "-s", "2020-01-01"], False),
    ("date --set", date, ["date", "--set=2020-01-01"], False),

    # tmpwrite — writes confined to a temp dir.
    ("touch tmp", tmpwrite, ["touch", "/tmp/x"], True),
    ("touch etc", tmpwrite, ["touch", "/etc/x"], False),
    ("touch mixed", tmpwrite, ["touch", "/tmp/a", "/etc/b"], False),
    ("mkdir -p tmp", tmpwrite, ["mkdir", "-p", "/tmp/a/b"], True),
    ("mkdir -m arg", tmpwrite, ["mkdir", "-m", "755", "/tmp/d"], False),  # mode arg not a temp path
    ("touch -- tmp", tmpwrite, ["touch", "--", "/tmp/x"], True),
    ("tee tmp", tmpwrite, ["tee", "-a", "/tmp/log"], True),
    ("rm -rf tmp", tmpwrite, ["rm", "-rf", "/tmp/x"], True),
    ("rm etc", tmpwrite, ["rm", "/etc/x"], False),
    ("touch no operand", tmpwrite, ["touch"], False),
    ("tmp traversal", tmpwrite, ["touch", "/tmp/../etc/passwd"], False),
    ("tmp prefix trap", tmpwrite, ["touch", "/tmpfoo"], False),
    ("tmpdir var", tmpwrite, ["touch", "$TMPDIR/x"], True),
    ("private tmp", tmpwrite, ["touch", "/private/tmp/x"], True),
    ("mv all tmp", tmpwrite, ["mv", "/tmp/a", "/tmp/b"], True),
    ("mv both tmp flag", tmpwrite, ["mv", "-f", "/tmp/a", "/tmp/b"], True),
    ("mv dest etc", tmpwrite, ["mv", "/tmp/a", "/etc/b"], False),
    ("mv src etc", tmpwrite, ["mv", "/etc/a", "/tmp/b"], False),  # mv removes source
    ("mv target-dir long", tmpwrite, ["mv", "--target-directory=/etc", "/tmp/x"], False),
    ("mv target-dir attached", tmpwrite, ["mv", "-t/root/.ssh", "/tmp/x"], False),
    ("mv target-dir sep", tmpwrite, ["mv", "-t", "/etc", "/tmp/x"], False),
    # cp — source unrestricted, dest must be temp.
    ("cp src outside", tmpwrite, ["cp", "/etc/hosts", "/tmp/h"], True),
    ("cp -r src outside", tmpwrite, ["cp", "-r", "src", "/tmp/d"], True),
    ("cp dest outside", tmpwrite, ["cp", "/tmp/a", "/etc/b"], False),
    ("cp target-dir flag", tmpwrite, ["cp", "-t", "/etc", "src", "/tmp/x"], False),
    ("cp long flag", tmpwrite, ["cp", "--target-directory=/etc", "src"], False),
    ("cp one operand", tmpwrite, ["cp", "/tmp/x"], False),

    # xargs — allowed only when the wrapped command is an operand-independent
    # pure read; xargs injects unseen stdin operands, so temp-write wrapped
    # commands (operand-dependent) and unknown commands defer.
    ("xargs grep", xargs, ["xargs", "grep", "-l", "foo"], True),
    ("xargs -0 grep", xargs, ["xargs", "-0", "grep", "x"], True),
    ("xargs -n1 cat", xargs, ["xargs", "-n1", "cat"], True),
    ("xargs -n sep", xargs, ["xargs", "-n", "1", "cat"], True),
    ("xargs -I{} grep", xargs, ["xargs", "-I", "{}", "grep", "x", "{}"], True),
    ("xargs -I attached", xargs, ["xargs", "-I{}", "grep", "x", "{}"], True),
    ("xargs bare echo", xargs, ["xargs"], True),
    ("xargs -- grep", xargs, ["xargs", "--", "grep", "x"], True),
    ("xargs rm", xargs, ["xargs", "rm"], False),  # injects unseen paths to delete
    ("xargs rm tmp", xargs, ["xargs", "rm", "/tmp/x"], False),  # operand-dependent allow
    ("xargs sed -i", xargs, ["xargs", "sed", "-i", "s/a/b/"], False),
    ("xargs bash", xargs, ["xargs", "bash", "-c", "echo"], False),  # unknown command
    ("xargs -i deprecated", xargs, ["xargs", "-i", "grep", "x"], False),  # optional-arg flag
    ("xargs unknown opt", xargs, ["xargs", "--foo", "grep", "x"], False),
]


def main() -> int:
    failures = []
    for label, mod, tokens, expected in CASES:
        ok, _reason = mod.classify(tokens)
        status = "ok" if ok == expected else "FAIL"
        if ok != expected:
            failures.append((label, tokens, ok, expected))
        print(f"[{status}] {label}: got ok={ok}, want {expected}")

    # Registry sanity: representative names resolve to the right module.
    expected_registry = {
        "cat": readonly.classify, "grep": readonly.classify,
        "cd": readonly.classify,
        "find": find.classify, "sed": sed.classify, "awk": awk.classify,
        "gh": gh.classify, "git": git.classify, "env": env.classify,
        "command": command.classify, "curl": curl.classify,
        "date": date.classify,
        "sort": sort.classify, "yq": yq.classify,
        "xargs": xargs.classify,
        "touch": tmpwrite.classify, "cp": tmpwrite.classify,
    }
    for name, fn in expected_registry.items():
        got = CLASSIFIERS.get(name)
        status = "ok" if got is fn else "FAIL"
        if got is not fn:
            failures.append((f"registry[{name}]", None, got, fn))
        print(f"[{status}] registry[{name}] resolves correctly")

    print()
    total = len(CASES) + len(expected_registry)
    if failures:
        print(f"{len(failures)}/{total} FAILED:")
        for label, tokens, got, want in failures:
            print(f"  {label}: got {got!r}, want {want!r} (tokens={tokens})")
        return 1
    print(f"All {total} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
