# Claude Code hooks

## `bash-guard.py` — read-only Bash auto-approval

A `PreToolUse` hook (matcher: `Bash`) that **auto-approves provably read-only
shell commands — including pipelines** — so they run without a permission
prompt. It is the single source of truth for read-only `Bash` access; there are
no `Bash(...)` entries in `settings.json` → `permissions.allow`.

`bash-guard.py` is a thin entrypoint shim; the logic lives in the `guard`
package next to it (see [Layout](#layout)).

### Wiring

Registered in `~/.claude/settings.json`:

```json
"hooks": {
  "PreToolUse": [
    {
      "matcher": "Bash",
      "hooks": [
        { "type": "command", "command": "/Users/gonzalo.abella/.claude/hooks/bash-guard/bash-guard.py" }
      ]
    }
  ]
}
```

> If this hook is removed, disabled, or its path changes, read-only Bash
> commands simply go back to prompting — nothing breaks, you just lose the
> auto-approval convenience.

### Core design principle: it can only *add* auto-approval

The hook has exactly **two** outcomes:

- **`allow`** — the command is fully parsed and proven read-only.
- **defer** (exit 0, no output) — hand the decision back to Claude Code's normal
  permission flow (`deny` → `ask` → `allow` rules, else prompt).

It **never** emits `ask` or `deny`. This is deliberate and verified against the
Claude Code docs:

> A hook's JSON `ask`/`deny` does **not** reliably override a settings `allow`
> rule — only exit code 2 does. Deny/ask settings rules are evaluated regardless
> of the hook.

So emitting `ask` would give no guaranteed safety benefit while risking spurious
prompts for commands you've explicitly allow-listed. By only ever `allow`-ing or
deferring, the hook is **incapable of blocking a command or introducing a
security hole** — the worst it can do is fail to auto-approve something, which
falls back to a normal prompt.

### How a command is judged

1. **Bail-outs → defer.** Command/process substitution (`$(…)`, backticks,
   `<(…)`, `>(…)`), subshell grouping `( … )`, output redirects to a real file
   (`>`, `>>`, and the combined `>&file` / `&>file` / `&>>file` forms), `<>`
   read-write opens, and unbalanced quotes are never auto-approved. Redirects
   that only **discard**, **duplicate** a descriptor, or **write into a temp
   dir** are harmless and do not block auto-approval: `>/dev/null`,
   `2>/dev/null`, fd duplications `2>&1` / `>&2`, and writes confined to a temp
   dir — `>/tmp/out`, `2>/tmp/err`, `>>/private/tmp/log`, `>$TMPDIR/f` (see
   `guard/paths.py`).

   > ⚠️ Redirect parsing has a sharp edge. `shlex(punctuation_chars=…)` collapses
   > runs of punctuation into one token, so `2>&1` lexes as `2`, `>&`, `1`. The
   > `&`-containing operators (`>&`, `&>`, `&>>`) must therefore be matched
   > explicitly — a bare `>`/`>>` check misses `grep x f >&out.log`, which
   > writes a file and would otherwise be wrongly auto-approved. A numeric
   > target counts as an fd duplication (harmless) only for the `>&`/`&>` forms;
   > for a plain `>`, `1>2` means the file named `2` (a write).
2. **Tokenize** with Python `shlex` (`punctuation_chars`), which separates real
   shell operators from quoted ones — e.g. `grep 'a|b' | sort` is parsed
   correctly. Comment handling is disabled (`commenters = ""`) so an unquoted
   `#` can't silently truncate a token and hide a trailing mutating flag
   (e.g. `find . -name a#b -delete`).
3. **Split** into segments on `|`, `||`, `&&`, `;`, `&`.
4. **Strip leading `VAR=value` assignments** from each segment so
   `FOO=bar grep x` classifies on `grep`; a segment that is *only* assignments
   (`FOO=bar`) is itself read-only. Only leading assignments are dropped, never
   later operands (e.g. grep's `x=y`).
5. **Classify each segment.** The whole command is auto-allowed **only if every
   segment is read-only**. Any mutating or unknown segment → defer.

Input redirects (`<`) are treated as read-only; their target token is dropped so
it isn't mistaken for a command.

### What counts as read-only

- **Pure read utilities** (`classifiers/readonly.py`) — allowed with no argument
  inspection: `cat`, `head`, `tail`, `grep`, `rg`, `uniq`, `cut`, `tr`,
  `wc`, `jq`, `ls`, `stat`, `file`, `tree`, `diff`, `whoami`, `id`, `ps`,
  `which`, `printenv`, `pwd`, `realpath`, `readlink`, `cd`/`pushd`/`popd`/`dirs`
  (dir navigation only), … (see `readonly.py`'s `NAMES` for the full set).
  Note `sort` and `yq` are **not** here — each can write via a flag, so they get
  inspected classifiers below.
- **Inspected commands** — read-only *only in certain forms*, so their arguments
  are checked. Each lives in its own file under `classifiers/`:

  | Command   | Auto-allowed when…                        | Defers when… |
  |-----------|-------------------------------------------|--------------|
  | `find`    | no executing/mutating action              | `-exec`, `-execdir`, `-ok(dir)`, `-delete`, `-fprint*`, `-fls` |
  | `sed`     | not in-place                              | `-i` / `--in-place` |
  | `sort`    | streams to stdout                         | `-o` / `--output` (writes a file), incl. bundled `-rno FILE` |
  | `yq`      | reads / reformats                         | `-i` / `--inplace` / `--in-place` (edits the file), incl. bundled `-iP` |
  | `awk`     | no shell-out / file output                | `system(`, `getline`, `print > …` |
  | `git`     | read subcommand (`status`, `log`, `diff`, `show`, `branch`, `blame`, `remote`, `rev-parse`, `ls-*`, `merge-base`, `check-ignore`, `git grep`, …); `config --get/--list`; `tag`/`tag -l`; `stash list/show`; `worktree list`; `submodule status/summary` | writes, `git tag <name>`, `config` set/`--unset`, `stash`/`worktree add`/`submodule update`, `-c`/`-C`/`--exec-path` global flags |
  | `gh api`  | GET (no method/body flags)                | `-X/--method POST\|PUT\|PATCH\|DELETE`, `-f/-F/--field/--raw-field/--input` |
  | `gh` (other) | read subcommand (`pr view/list/diff/checks/status`, `run view/list`, `issue`, `repo view/list`, `auth status`, `gist list/view`, …) | any other subcommand (`pr create`, `pr merge`, …) |
  | `env`     | bare, or only `NAME=VALUE` assignments    | any bare operand (it would *run* that command), unknown options |
  | `command` | `command -v/-V NAME` (lookup)             | `command NAME …` (it *runs* NAME) |
  | `date`    | reading/formatting                        | `-s` / `--set` (sets the system clock) |
  | `touch` `mkdir` `tee` `rm` `mv` | every operand is a temp path (`/tmp/…`, `/private/tmp/…`, `$TMPDIR/…`) | any operand outside a temp dir, or a `..` escape |
  | `cp`      | destination (last operand) is a temp path; sources may be anywhere (read-only) | destination outside a temp dir, or any non-arg-less flag (e.g. `-t` / `--target-directory`) |

Any command with no registered classifier → defer (normal prompt).

### Audit log

Every decision is appended to `bash-guard.log` (next to `bash-guard.py`) as one
JSON object per line — `{ts, decision, reason, command}`:

```jsonl
{"ts":"2026-08-03T14:23:08+00:00","decision":"allow","reason":"read-only command / pipeline","command":"git log | grep FIX"}
{"ts":"2026-08-03T14:23:08+00:00","decision":"defer","reason":"unknown command: rsync","command":"rsync -a a b"}
```

The point is **tuning the guard over time**: the `defer` records and their
`reason` (e.g. `unknown command: rsync`, `sed -i is in-place`) show which
commands/forms are worth teaching the guard to auto-allow. Aggregate them, e.g.:

```bash
# Most-frequently-deferred commands, most common first.
jq -r 'select(.decision=="defer") | .reason' \
  ~/.claude/hooks/bash-guard/bash-guard.log | sort | uniq -c | sort -rn
```

- **Multi-line commands** stay one physical line — embedded newlines are escaped
  as `\n` inside the JSON string, so `jq` round-trips them intact.
- **Auto-trim:** logging is fail-safe (any error is swallowed — it can never
  break the shell) and the file is capped at ~1 MB; when exceeded, the oldest
  half is dropped in place on the next write. See `guard/audit.py`.
- **Override the path** with `BASH_GUARD_LOG` (used by the tests; point it at
  `/dev/null` to disable logging).

### Layout

```
bash-guard/
├── bash-guard.py            # entrypoint shim -> guard.cli.main
├── bash-guard.log           # JSONL audit log (auto-created, auto-trimmed)
├── guard/
│   ├── decision.py          # emit() / defer()  (both log to the audit log)
│   ├── audit.py             # append-only JSONL decision log + auto-trim
│   ├── parser.py            # shlex tokenizing + segment splitting + leading-assignment strip + bail-outs
│   ├── redirects.py         # redirect operators + strip_redirects()
│   ├── paths.py             # is_tmp_path(): temp-dir write predicate
│   ├── cli.py               # main(): stdin JSON -> allow/defer orchestration
│   ├── registry.py          # command name -> classifier dispatch table
│   └── classifiers/
│       ├── base.py          # ALLOW / deny() result contract
│       ├── readonly.py      # pure read utilities (NAMES)
│       ├── tmpwrite.py      # writes confined to a temp dir (touch/mkdir/tee/rm/mv/cp)
│       └── find.py, sed.py, sort.py, yq.py, awk.py, gh.py, git.py, env.py, command.py, date.py
└── test_bash_guard.py       # end-to-end suite (drives the shim over stdin)
```

Each `classifiers/*.py` module exposes `NAMES` (the command names it handles)
and `classify(tokens) -> (ok, reason)`. `registry.py` folds every module's
`NAMES` onto its `classify`; membership in that map is also what "we recognize
this command" means.

### Editing / extending

- Add a pure read utility → append it to `NAMES` in `classifiers/readonly.py`.
- Add a command that's read-only only in some forms → create
  `classifiers/<cmd>.py` with `NAMES` + a `classify()` returning `ALLOW` for the
  safe form and `deny(reason)` otherwise, then register the module in
  `registry.py`'s `_MODULES`. **When in doubt, `deny`** (defer) — the hook's
  safety rests on never `allow`-ing something it hasn't proven read-only.
- Widen `gh` reads → edit `GH_READ` in `classifiers/gh.py`. Widen `git` reads →
  edit `GIT_READ` in `classifiers/git.py` (pure-read subcommands only; anything
  read-only *only in some forms* — like `config`, `tag`, `stash` — gets a
  dedicated branch in that file's `classify()`).
- After any change, add matching `ALLOW`/`DEFER` cases and run
  `test_bash_guard.py`.

### Testing

Three stdlib-only suites, each exits 1 on any failure — run them after any edit:

```bash
python3 ~/.claude/hooks/bash-guard/test_bash_guard.py    # end-to-end (over stdin)
python3 ~/.claude/hooks/bash-guard/test_classifiers.py   # per-classifier units
python3 ~/.claude/hooks/bash-guard/test_audit.py         # audit log + auto-trim
```

- **`test_bash_guard.py`** drives the whole hook through the shim over stdin —
  it covers the read-only and inspected commands, pipelines, redirects, and the
  `#`-truncation guard. Add a case to its `ALLOW` (must auto-approve) or `DEFER`
  (must fall back to a prompt) list whenever you extend the hook.
- **`test_classifiers.py`** calls each `classify(tokens)` directly, so a failure
  points straight at the offending command's module. Add a case here when you
  add or change a classifier's allow/deny logic.

The registry itself is fail-loud: two modules claiming the same name in `NAMES`
raise at import (`duplicate classifier registration`). And `main()` wraps its
work so any *unexpected* error defers rather than crashing — this hook runs on
every Bash call, so it must never break the shell flow.

The hook reads a `PreToolUse` JSON payload on stdin and prints a decision (or
nothing) on stdout. Quick manual check:

```bash
jq -n --arg c 'git log | grep FIX' '{tool_input:{command:$c}}' \
  | python3 ~/.claude/hooks/bash-guard/bash-guard.py
# -> {"hookSpecificOutput":{...,"permissionDecision":"allow",...}}

jq -n --arg c 'grep x f | tee out' '{tool_input:{command:$c}}' \
  | python3 ~/.claude/hooks/bash-guard/bash-guard.py
# -> (no output; exit 0 => defers to normal permission flow)
```
