#!/usr/bin/env python3
"""Unit tests for the individual classifiers.

Complements test_bash_guard.py (which drives the whole hook over stdin) by
exercising each ``classify(tokens) -> (ok, reason)`` function directly. Faster,
and a failure points straight at the offending command's module.

Tokens here are already post-shlex (``tokens[0]`` is the command), exactly what
the orchestrator passes in. Stdlib-only, like the sibling suite.

    python3 test_classifiers.py     # -> prints a summary, exits 1 on any failure
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from guard.classifiers import (  # noqa: E402
    awk, bash, command, curl, date, docker, env, find, gh, git, kubectl,
    psql, readonly, sed, sort, tmpwrite, xargs, yq,
)
from guard.classifiers.subcommand import find_subcommand  # noqa: E402
from guard.registry import CLASSIFIERS  # noqa: E402

# `bash <path>` only recurses into scripts under a trusted root (real
# `~/.claude`); point it at a throwaway temp dir for the duration of this
# test run so these cases never touch the real one.
_BASH_SCRIPT_ROOT = tempfile.mkdtemp()
bash._TRUSTED_SCRIPT_ROOTS = (_BASH_SCRIPT_ROOT,)

_BASH_READONLY_SCRIPT = os.path.join(_BASH_SCRIPT_ROOT, "readonly.sh")
with open(_BASH_READONLY_SCRIPT, "w") as _f:
    _f.write("#!/usr/bin/env bash\necho hi\n")

_BASH_MUTATING_SCRIPT = os.path.join(_BASH_SCRIPT_ROOT, "mutating.sh")
with open(_BASH_MUTATING_SCRIPT, "w") as _f:
    _f.write("#!/usr/bin/env bash\nrm -rf /\n")

# (label, classifier, tokens, expected_ok)
CASES = [
    # readonly — always read-only, no arg inspection.
    ("readonly cat", readonly, ["cat", "x"], True),
    ("readonly grep", readonly, ["grep", "-r", "foo", "."], True),
    ("readonly cd", readonly, ["cd", "/tmp"], True),
    ("readonly pushd", readonly, ["pushd", "/x"], True),
    ("readonly sleep", readonly, ["sleep", "0.5"], True),
    ("readonly javap", readonly, ["javap", "-c", "-p", "Foo.class"], True),

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
    # Escaped `\(`/`\)` reach the classifier as literal `(`/`)` operands.
    ("find parens", find,
     ["find", ".", "(", "-name", "*.kt", "-o", "-name", "*.yml", ")"], True),
    ("find parens delete", find,
     ["find", ".", "(", "-name", "*.kt", ")", "-delete"], False),
    # -exec payload recurses through the same APPEND_SAFE gate as xargs.
    ("find exec grep semicolon", find,
     ["find", ".", "-name", "*.kt", "-exec", "grep", "-l", "Foo", "{}", ";"], True),
    ("find exec cat plus", find,
     ["find", ".", "-name", "*.kt", "-exec", "cat", "{}", "+"], True),
    ("find exec rm append-safety regression guard", find,
     ["find", ".", "-exec", "rm", "{}", ";"], False),
    ("find exec cp append-safety regression guard", find,
     ["find", ".", "-exec", "cp", "{}", "/tmp/dst", ";"], False),
    ("find exec sh -c unknown wrapped command", find,
     ["find", ".", "-exec", "sh", "-c", "cat $0", "{}", ";"], False),
    ("find exec no terminator", find,
     ["find", ".", "-exec", "cat", "{}"], False),
    ("find exec no wrapped command", find,
     ["find", ".", "-exec", ";"], False),
    ("find exec wraps sed -i still deferred", find,
     ["find", ".", "-exec", "sed", "-i", "s/a/b/", "{}", ";"], False),
    ("find multiple exec clauses, second unsafe", find,
     ["find", ".", "-name", "a", "-exec", "cat", "{}", ";",
      "-o", "-name", "b", "-exec", "rm", "{}", ";"], False),
    ("find execdir unchanged hard deny", find,
     ["find", ".", "-execdir", "cat", "{}", ";"], False),

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

    # psql — connection-info flags + a single safe SELECT/meta-command via -c.
    ("psql meta-command", psql,
     ["psql", "-h", "h", "-U", "u", "-d", "d", "-c", "\\dt"], True),
    ("psql dsn positional select", psql,
     ["psql", "host=localhost dbname=d", "-c", "select 1"], True),
    ("psql trailing semicolon ok", psql,
     ["psql", "-c", "SELECT * FROM accounts;"], True),
    ("psql attached -c", psql, ["psql", "-cselect 1"], True),
    ("psql long flags with =", psql,
     ["psql", "--host=h", "--username=u", "--dbname=d", "--command=select 1"], True),
    ("psql expanded + meta with plus", psql, ["psql", "-x", "-c", "\\dt+"], True),
    ("psql bare dbname/username positionals", psql,
     ["psql", "mydb", "myuser", "-c", "select 1"], True),
    ("psql chained statement", psql,
     ["psql", "-h", "h", "-c", "select 1; drop table x"], False),
    ("psql -f file", psql, ["psql", "-f", "script.sql"], False),
    ("psql --file=", psql, ["psql", "--file=script.sql"], False),
    ("psql non-select command", psql, ["psql", "-c", "update x set y=1"], False),
    ("psql copy meta-command denied", psql,
     ["psql", "-c", "\\copy (select 1) to stdout"], False),
    ("psql select into denied", psql,
     ["psql", "-c", "select * into t from x"], False),
    ("psql cte smuggling insert denied", psql,
     ["psql", "-c", "with x as (insert into t default values returning *) select * from x"],
     False),
    ("psql shell escape meta-command denied", psql, ["psql", "-c", "\\! rm -rf /"], False),
    ("psql include file meta-command denied", psql, ["psql", "-c", "\\i /etc/passwd"], False),
    ("psql multiple -c one bad", psql,
     ["psql", "-c", "select 1", "-c", "delete from x"], False),
    ("psql ambiguous bundled flag", psql, ["psql", "-xc", "select 1"], False),
    ("psql flag outside allowlist", psql, ["psql", "-w", "-c", "select 1"], False),
    ("psql embedded newline denied", psql, ["psql", "-c", "select 1\ndrop table x"], False),

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
    # issue #17: an unrecognized value-taking global flag must not be misread
    # as boolean-and-skip -- the real (mutating) subcommand after it must
    # still be inspected, not hidden as harmless trailing args.
    ("git --git-dir value misread as subcommand", git,
     ["git", "--git-dir", "status", "commit", "-m", "x"], False),
    ("git --work-tree value misread as subcommand", git,
     ["git", "--work-tree", "log", "push"], False),

    # docker — pure reads + conditional subcommands.
    ("docker ps", docker, ["docker", "ps"], True),
    ("docker logs", docker, ["docker", "logs", "x"], True),
    ("docker info", docker, ["docker", "info"], True),
    ("docker inspect", docker, ["docker", "inspect", "x"], True),
    ("docker --version", docker, ["docker", "--version"], True),
    ("docker context ls", docker, ["docker", "context", "ls"], True),
    ("docker context rm", docker, ["docker", "context", "rm", "x"], False),
    ("docker compose ps", docker, ["docker", "compose", "ps"], True),
    ("docker compose up", docker, ["docker", "compose", "up", "-d"], False),
    ("docker compose down", docker, ["docker", "compose", "down"], False),
    ("docker compose bare", docker, ["docker", "compose"], False),
    ("docker exec", docker, ["docker", "exec", "-it", "x", "sh"], False),
    ("docker bare", docker, ["docker"], False),
    # issue #17: --context takes a separate value; misreading it as boolean
    # let "ps" be mistaken for the subcommand while the real "run" was hidden.
    ("docker --context value misread as subcommand", docker,
     ["docker", "--context", "ps", "run", "alpine", "bash"], False),

    # kubectl — read verbs + conditional config.
    ("kubectl get", kubectl, ["kubectl", "get", "pods"], True),
    ("kubectl -n get", kubectl, ["kubectl", "-n", "ns", "get", "svc"], True),
    ("kubectl describe", kubectl, ["kubectl", "describe", "pod", "x"], True),
    ("kubectl config current-context", kubectl,
     ["kubectl", "config", "current-context"], True),
    ("kubectl config view", kubectl, ["kubectl", "config", "view"], True),
    ("kubectl config set", kubectl,
     ["kubectl", "config", "set-context", "x"], False),
    ("kubectl delete", kubectl, ["kubectl", "delete", "pod", "x"], False),
    ("kubectl apply", kubectl, ["kubectl", "apply", "-f", "x.yaml"], False),
    ("kubectl bare", kubectl, ["kubectl"], False),
    ("kubectl namespace only bare", kubectl, ["kubectl", "-n", "ns"], False),
    # issue #17: --as takes a separate value (impersonated user); the old
    # unrecognized-flags-are-boolean loop misread that value as the
    # subcommand and hid the real, mutating "delete" after it.
    ("kubectl --as value misread as subcommand", kubectl,
     ["kubectl", "--as", "get", "delete", "pod", "x"], False),
    ("kubectl --as with real read subcommand", kubectl,
     ["kubectl", "--as", "bob", "get", "pods"], True),

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

    # xargs — recurses into an append-safe wrapped command only.
    ("xargs grep", xargs, ["xargs", "grep", "-l", "Foo"], True),
    ("xargs wc", xargs, ["xargs", "wc", "-l"], True),
    ("xargs -0 -n opts then grep", xargs,
     ["xargs", "-0", "-n", "10", "grep", "-l", "y"], True),
    ("xargs -n attached", xargs, ["xargs", "-n5", "grep", "y"], True),
    ("xargs -- separator", xargs, ["xargs", "--", "grep", "-l", "y"], True),
    ("xargs wraps sed non-inplace", xargs, ["xargs", "sed", "-n", "1,5p"], True),
    ("xargs no wrapped command", xargs, ["xargs"], False),
    ("xargs only its own flags", xargs, ["xargs", "-0", "-n", "5"], False),
    ("xargs rm append-safety regression guard", xargs,
     ["xargs", "rm", "/tmp/safe"], False),
    ("xargs cp -t", xargs, ["xargs", "cp", "-t", "/tmp/dst"], False),
    ("xargs sh -c", xargs, ["xargs", "sh", "-c", "cat $0"], False),
    ("xargs unknown wrapped command", xargs, ["xargs", "notarealcmd"], False),
    # bash is a known command now (issue #13) but not append-safe, so
    # wrapping it via xargs must still defer, same as before registration.
    ("xargs wraps bash -c (not append-safe)", xargs,
     ["xargs", "bash", "-c", "echo hi"], False),
    ("xargs wraps sed -i still deferred", xargs,
     ["xargs", "sed", "-i", "s/a/b/"], False),
    ("xargs wraps sort -o deferred", xargs, ["xargs", "sort", "-o", "out"], False),
    ("xargs wraps curl (not append-safe)", xargs,
     ["xargs", "curl", "https://x"], False),
    ("xargs wraps env (not append-safe)", xargs, ["xargs", "env", "FOO=1"], False),
    ("xargs -I replace deny", xargs, ["xargs", "-I{}", "echo", "{}"], False),
    ("xargs -i bare replace deny", xargs, ["xargs", "-i", "echo", "{}"], False),
    ("xargs --replace deny", xargs, ["xargs", "--replace", "echo", "{}"], False),
    ("xargs -J BSD replace deny", xargs, ["xargs", "-J", "%", "echo", "%"], False),
    ("xargs unrecognized flag deny", xargs,
     ["xargs", "--totally-bogus", "grep", "y"], False),
    ("xargs nested xargs defers", xargs, ["xargs", "xargs", "grep", "y"], False),

    # bash -c — recurses the inline script through the same classify
    # pipeline (issue #13, phase 1).
    ("bash -c read-only script", bash, ["bash", "-c", "echo hi"], True),
    ("bash -c mutating script", bash, ["bash", "-c", "rm -rf /"], False),
    ("bash -c with positional args stays read-only", bash,
     ["bash", "-c", "echo $1", "ignored"], True),
    ("bash -c wrapping unknown command", bash,
     ["bash", "-c", "notarealcmd"], False),
    # bash <path> — recurses a script file read off disk, only when it
    # resolves under a trusted root (issue #26, phase 2).
    ("bash <path> outside any trusted root defers", bash,
     ["bash", "/some/script.sh"], False),
    ("bash <path> trusted root, read-only script", bash,
     ["bash", _BASH_READONLY_SCRIPT], True),
    ("bash <path> trusted root, with positional args stays read-only", bash,
     ["bash", _BASH_READONLY_SCRIPT, "arg1"], True),
    ("bash <path> trusted root, mutating script", bash,
     ["bash", _BASH_MUTATING_SCRIPT], False),
    ("bash <path> existing file outside trusted root defers", bash,
     ["bash", "/etc/hostname"], False),
    ("bash <path> nonexistent file under trusted root defers", bash,
     ["bash", os.path.join(_BASH_SCRIPT_ROOT, "missing.sh")], False),
    ("bash <path> relative path defers", bash,
     ["bash", "relative/script.sh"], False),
    ("bash bare defers", bash, ["bash"], False),
    ("bash -c with extra leading flag defers (narrow shape)", bash,
     ["bash", "-x", "-c", "echo hi"], False),
]

# (label, tokens, value_flags, expected_result) — direct unit tests for the
# shared find_subcommand() helper (guard/classifiers/subcommand.py), which
# git/docker/kubectl all delegate to (issue #17).
SUBCOMMAND_CASES = [
    ("no flags", ["git", "status"], frozenset(), ("status", [])),
    ("value flag skipped", ["kubectl", "-n", "ns", "get", "pods"],
     frozenset({"-n"}), ("get", ["pods"])),
    ("unrecognized flag fails safe", ["git", "--git-dir", "status"],
     frozenset(), (None, None)),
    ("value flag's own value never mistaken for subcommand",
     ["docker", "--context", "ps", "run"], frozenset({"--context"}),
     ("run", [])),
    ("bare command fails safe", ["git"], frozenset(), (None, None)),
    ("only flags, no bare word fails safe", ["kubectl", "-n", "ns"],
     frozenset({"-n"}), (None, None)),
]


def main() -> int:
    failures = []
    for label, mod, tokens, expected in CASES:
        ok, _reason = mod.classify(tokens)
        status = "ok" if ok == expected else "FAIL"
        if ok != expected:
            failures.append((label, tokens, ok, expected))
        print(f"[{status}] {label}: got ok={ok}, want {expected}")

    for label, tokens, value_flags, expected in SUBCOMMAND_CASES:
        got = find_subcommand(tokens, value_flags=value_flags)
        status = "ok" if got == expected else "FAIL"
        if got != expected:
            failures.append((f"find_subcommand[{label}]", tokens, got, expected))
        print(f"[{status}] find_subcommand: {label}: got {got}, want {expected}")

    # Registry sanity: representative names resolve to the right module.
    expected_registry = {
        "cat": readonly.classify, "grep": readonly.classify,
        "cd": readonly.classify,
        "find": find.classify, "sed": sed.classify, "awk": awk.classify,
        "gh": gh.classify, "git": git.classify, "env": env.classify,
        "docker": docker.classify, "kubectl": kubectl.classify,
        "command": command.classify, "curl": curl.classify,
        "date": date.classify, "psql": psql.classify,
        "sort": sort.classify, "yq": yq.classify,
        "touch": tmpwrite.classify, "cp": tmpwrite.classify,
        "xargs": xargs.classify, "bash": bash.classify,
    }
    for name, fn in expected_registry.items():
        got = CLASSIFIERS.get(name)
        status = "ok" if got is fn else "FAIL"
        if got is not fn:
            failures.append((f"registry[{name}]", None, got, fn))
        print(f"[{status}] registry[{name}] resolves correctly")

    print()
    total = len(CASES) + len(SUBCOMMAND_CASES) + len(expected_registry)
    if failures:
        print(f"{len(failures)}/{total} FAILED:")
        for label, tokens, got, want in failures:
            print(f"  {label}: got {got!r}, want {want!r} (tokens={tokens})")
        return 1
    print(f"All {total} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
