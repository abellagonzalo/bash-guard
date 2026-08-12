# AGENTS.md

Guidance for AI agents and human contributors working **inside** the `bash-guard`
repository. If you are here to change code, read this first. For a project overview and
setup, see [`README.md`](./README.md).

## Prime directive: the guard can only *add* auto-approval

`bash-guard` is a Claude Code `PreToolUse` hook (matcher: `Bash`) that auto-approves
provably read-only shell commands — including pipelines — so they run without a
permission prompt.

The hook has exactly **two** outcomes:

- **`allow`** — the command is fully parsed and proven read-only.
- **defer** (exit 0, no output) — hand the decision back to Claude Code's normal
  permission flow (`deny` → `ask` → `allow` rules, else prompt).

It **never** emits `ask` or `deny`. This is deliberate and verified against the Claude
Code docs: a hook's JSON `ask`/`deny` does **not** reliably override a settings `allow`
rule — only exit code 2 does. So emitting `ask` would give no guaranteed safety benefit
while risking spurious prompts for commands the user has explicitly allow-listed. By only
ever `allow`-ing or deferring, the hook is **incapable of blocking a command or
introducing a security hole** — the worst it can do is fail to auto-approve something,
which falls back to a normal prompt.

> **When in doubt, defer.** The guard's safety rests entirely on never `allow`-ing
> something it hasn't proven read-only. A classifier that is unsure must `deny(reason)`
> (which defers), never `ALLOW`.

## Architecture / layout

`bash-guard.py` is a thin entrypoint shim; the logic lives in the `guard` package.

```
bash-guard/
├── bash-guard.py            # entrypoint shim -> guard.cli.main()
├── bash-guard.log           # JSONL audit log (auto-created, auto-trimmed, gitignored)
├── guard/
│   ├── cli.py               # main(): stdin JSON -> allow/defer orchestration
│   ├── decision.py          # emit() / defer()  (both log to the audit log)
│   ├── audit.py             # append-only JSONL decision log + auto-trim (~1 MB)
│   ├── parser.py            # shlex tokenizing, segment splitting, leading-assignment strip, bail-outs
│   ├── redirects.py         # redirect operators + strip_redirects()
│   ├── paths.py             # is_tmp_path(): temp-dir write predicate
│   ├── registry.py          # command name -> classifier dispatch table + APPEND_SAFE map (built at import)
│   └── classifiers/
│       ├── base.py          # ALLOW / deny() result contract
│       ├── readonly.py      # pure read utilities (NAMES)
│       ├── tmpwrite.py      # writes confined to a temp dir (touch/mkdir/tee/rm/mv/cp)
│       ├── xargs.py         # recurses into an append-safe wrapped command
│       └── find.py, sed.py, sort.py, yq.py, awk.py, git.py, gh.py, curl.py, env.py, command.py, date.py
└── test_bash_guard.py, test_classifiers.py, test_audit.py
```

Each `classifiers/*.py` module exposes `NAMES` (the command names it handles) and
`classify(tokens) -> (ok, reason)`. `registry.py` folds every module's `NAMES` onto its
`classify`; membership in that map is also what "we recognize this command" means. The
registry is **fail-loud**: two modules claiming the same name in `NAMES` raise at import
(`duplicate classifier registration`). `main()` wraps its work so any *unexpected* error
defers rather than crashing — this hook runs on every Bash call, so it must never break
the shell flow.

## How a command is judged

1. **Bail-outs → defer.** Command/process substitution (`$(…)`, backticks, `<(…)`,
   `>(…)`), *unquoted* subshell grouping `( … )`, ANSI-C quoting (`$'…'`), output redirects to a real file (`>`, `>>`, and the
   combined `>&file` / `&>file` / `&>>file` forms), `<>` read-write opens, and unbalanced
   quotes are never auto-approved. Redirects that only **discard**, **duplicate** a
   descriptor, or **write into a temp dir** are harmless and do not block auto-approval:
   `>/dev/null`, `2>/dev/null`, fd duplications `2>&1` / `>&2`, and writes confined to a
   temp dir — `>/tmp/out`, `2>/tmp/err`, `>>/private/tmp/log`, `>$TMPDIR/f` (see
   `guard/paths.py`).

   > ⚠️ **Subshell detection reads the RAW string, not the tokens.** `shlex` resolves
   > escapes before we see a token, so `\(` (a literal `find` operand) and a real subshell
   > `(` both lex to `(`. `guard/parser.py`'s `_needs_raw_bailout()` therefore walks the
   > raw command tracking bash's quoting forms (`\c`, `'…'` where a backslash is *not* an
   > escape, `"…"` where it is) and defers only on a paren that is genuinely unquoted and
   > unescaped. So `find . \( -name "*.kt" -o -name "*.yml" \)` and `find . '(' … ')'` are
   > auto-approved, while `(cd /tmp && ls)`, `f() { … }`, and `case x in a) …` still defer.
   > An unterminated quote returns "unquoted" so ambiguity always defers.
   >
   > This also **closed a false-allow**. Punctuation runs collapse, so `;(` lexes as one
   > token that is neither a segment separator nor equal to `"("` — the old token-list
   > check missed it entirely and `echo ;(rm -rf /tmp/zz);` was auto-approved even though
   > bash runs the subshell. Same for `||(` and the `()` in `f() { ls; }`.
   >
   > ⚠️ **The same walk bails out on ANSI-C `$'…'`.** Inside it bash *does* let a backslash
   > escape, including `\'`; this walk and shlex both read that `'` as the closing quote.
   > Two crafted occurrences shift the quote phase and shift it back, so both sides end
   > balanced and the unterminated-quote fail-safe never fires — `echo $'\''; rm -rf /tmp/x;
   > echo \'` runs the `rm` in bash while we read `; rm -rf /tmp/x; echo ` as the *contents*
   > of a string and auto-allow an `echo`. It is not paren-specific (that payload hides from
   > shlex with no paren anywhere), so the only fix is to refuse `$'…'` outright. Free in
   > practice: 0 of the 1554 unique commands in the audit log use it — the `$'` hits there
   > are all a regex `$` anchor before a closing quote, which the walk skips as quoted.
   > `$"…"` needs no case of its own; it quotes exactly like `"…"`.
   >
   > ⚠️ **The same walk bails out on a word-start `#` and on `<<`.** Bash treats a comment
   > body and a heredoc body as *inert*; neither this walk nor shlex (with
   > `commenters = ""`) does. An odd quote count in such a region shifts the quote phase
   > and a second one shifts it back, so both sides end balanced, no fail-safe fires, and a
   > later **real** command is swallowed as the contents of a string — `echo hi # don't` /
   > newline / `rm -rf ~ # it's` was auto-approved (issue #8). Two subtleties: the `#` test
   > is scoped to a **word start** (start of string, or after unquoted whitespace or one of
   > `;|&<>()`) so a mid-token `#` still lexes and `commenters = ""` keeps its meaning; and
   > `\` + newline is line continuation, so the character *before* the backslash decides
   > the word start — otherwise `echo hi \` / newline / `# don't` hides the same payload.
   > The `<<` test also catches `<<-` and `<<<`; a here-string cannot desync on its own,
   > but over-approximating costs one lookahead character. Free in practice: of the 1123
   > unique auto-allowed commands in the audit log, none carries a word-start `#` or an
   > unquoted `<<` (the two that match a naive grep have both inside `"…"`).

   > ⚠️ **Redirect parsing has a sharp edge.** `shlex(punctuation_chars=…)` collapses runs
   > of punctuation into one token, so `2>&1` lexes as `2`, `>&`, `1`. The `&`-containing
   > operators (`>&`, `&>`, `&>>`) must therefore be matched explicitly — a bare `>`/`>>`
   > check misses `grep x f >&out.log`, which writes a file and would otherwise be wrongly
   > auto-approved. A numeric target counts as an fd duplication (harmless) only for the
   > `>&`/`&>` forms; for a plain `>`, `1>2` means the file named `2` (a write).
2. **Tokenize** with Python `shlex` (`punctuation_chars`), which separates real shell
   operators from quoted ones — e.g. `grep 'a|b' | sort` parses correctly. Comment
   handling is disabled (`commenters = ""`) so an unquoted `#` can't silently truncate a
   token and hide a trailing mutating flag (e.g. `find . -name a#b -delete`). That works
   *with* the word-start `#` bail-out above, not against it: a real comment never reaches
   the lexer, and a mid-token `#` is an ordinary character to bash and to shlex alike.
3. **Split** into segments on `|`, `||`, `&&`, `;`, `&`.

   > ⚠️ **Same raw-string-vs-token desync, for `;`.** `find -exec cmd {} \;` needs its
   > terminator written as an escaped `\;` (or it lexes as `-o`/etc. before the shell ever
   > sees it), but `shlex` resolves that escape to a bare `;` token — indistinguishable
   > from a real segment separator. Splitting on it verbatim would cut the command in two
   > and silently drop the terminator (and anything meant to follow it). `guard/parser.py`'s
   > `_protect_escaped_semicolons()` walks the raw string (same quote-skip logic as
   > `_needs_raw_bailout`) and swaps every *unquoted* `\;` for a sentinel byte before
   > lexing, then restores it to a literal `;` token — never a separator — once segments are
   > built. Quoted forms (`';'`, `";"`) hit the same desync but aren't fixed; that's a
   > distinct, pre-existing bug (e.g. `grep ';' file` already mis-splits today), not a
   > regression.
4. **Strip leading `VAR=value` assignments** from each segment so `FOO=bar grep x`
   classifies on `grep`; a segment that is *only* assignments (`FOO=bar`) is itself
   read-only. Only leading assignments are dropped, never later operands (e.g. grep's
   `x=y`).
5. **Classify each segment.** The whole command is auto-allowed **only if every segment is
   read-only**. Any mutating or unknown segment → defer.

Input redirects (`<`) are treated as read-only; their target token is dropped so it isn't
mistaken for a command.

## Classifier reference

### Pure read utilities — `classifiers/readonly.py`

Allowed as any pipeline stage with no argument inspection. Append new pure-read commands
to `NAMES`. Current set includes `cat`, `head`, `tail`, `grep`/`rg`, `cut`, `tr`, `uniq`,
`wc`, `jq`, `ls`, `stat`, `file`, `tree`, `diff`, `whoami`, `id`, `ps`, `which`,
`printenv`, `pwd`, `realpath`, `readlink`, the directory-navigation builtins
(`cd`/`pushd`/`popd`/`dirs`), and system-info commands (`uname`, `df`, `du`, `free`, …).
See `readonly.py`'s `NAMES` for the authoritative list.

> `sort` and `yq` are **not** here — each can write via a flag, so they get inspected
> classifiers below.

### Inspected commands — read-only only in certain forms

Each lives in its own module under `classifiers/`; arguments are checked.

| Command | Auto-allowed when… | Defers when… |
|---------|--------------------|--------------|
| `find` | no executing/mutating action; `-exec cmd … {} \;`/`{} +` wraps a recognized, **append-safe** command whose own classifier allows the payload | `-execdir`, `-ok(dir)`, `-delete`, `-fprint*`, `-fls`; or an `-exec` with no `;`/`+` terminator, an unknown wrapped command, or a wrapped command that isn't append-safe or itself denies |
| `sed` | not in-place | `-i` / `--in-place` |
| `sort` | streams to stdout | `-o` / `--output` (writes a file), incl. bundled `-rno FILE` |
| `yq` | reads / reformats | `-i` / `--inplace` / `--in-place` (edits the file), incl. bundled `-iP` |
| `awk` | no shell-out / file output | `system(`, `getline`, `print > …` |
| `git` | read subcommand (`status`, `log`, `diff`, `show`, `branch`, `blame`, `remote`, `rev-parse`, `ls-*`, `merge-base`, `check-ignore`, `git grep`, …); `config --get/--list`; `tag`/`tag -l`; `stash list/show`; `worktree list`; `submodule status/summary` | writes, `git tag <name>`, `config` set/`--unset`, `stash`/`worktree add`/`submodule update`, `-c`/`-C`/`--exec-path` global flags |
| `gh api` | GET (no method/body flags) | `-X/--method POST\|PUT\|PATCH\|DELETE`, `-f/-F/--field/--raw-field/--input` |
| `gh` (other) | read subcommand (`pr view/list/diff/checks/status`, `run view/list`, `issue`, `repo view/list`, `auth status`, `gist list/view`, …) | any other subcommand (`pr create`, `pr merge`, …) |
| `curl` | GET/HEAD only, no request body/upload, response written only to a temp dir | non-GET verb (`-X POST`), body/upload flags (`-d`/`--data`/`-F`/`-T`/`--json`), output outside a temp dir (`-o`/`-O`), config files (`-K`), or a dangerous letter hidden in a short-flag bundle |
| `env` | bare, or only `NAME=VALUE` assignments | any bare operand (it would *run* that command), unknown options |
| `command` | `command -v/-V NAME` (lookup) | `command NAME …` (it *runs* NAME) |
| `date` | reading/formatting | `-s` / `--set` (sets the system clock) |
| `touch` `mkdir` `tee` `rm` `mv` | every operand is a temp path (`/tmp/…`, `/private/tmp/…`, `$TMPDIR/…`) | any operand outside a temp dir, or a `..` escape |
| `cp` | destination (last operand) is a temp path; sources may be anywhere (read-only) | destination outside a temp dir, or any non-arg-less flag (e.g. `-t` / `--target-directory`) |
| `xargs` | wraps a recognized, **append-safe** command whose own classifier allows the visible tokens | unrecognized/replace-string (`-I`/`-i`/`-J`/`--replace`) flags, no wrapped command, or the wrapped command is unknown, not append-safe, or itself denies |

Any command with no registered classifier → defer (normal prompt).

### Append-safe classifiers (`APPEND_SAFE` in `registry.py`)

`xargs` and `find -exec cmd … {} \;`/`{} +` append extra operands (the piped-in/matched
filenames) to the END of the wrapped command they actually run. A classifier that reasons
about operand *position* — e.g. `tmpwrite.py`'s `rm`/`cp`, which key off "last operand" /
"every operand" — can be fooled: the visible tokens `xargs rm /tmp/safe` look all-temp-safe,
but the real invocation is `rm /tmp/safe file1 file2 …`, deleting arbitrary paths. So such a
recursing classifier must never trust a wrapped classifier's ALLOW unless its module opts in
with a module-level `APPEND_SAFE = True` — meaning its verdict only depends on flags/script
text, never on operand position or completeness. Currently opted in: `readonly`, `find`,
`sed`, `sort`, `awk`, `yq`. Everything else (the `tmpwrite` family, `curl`, `env`, `command`,
`xargs` itself, …) stays unmarked, and a recursing classifier must skip calling it entirely
rather than call-then-ignore an ALLOW. See `classifiers/xargs.py` for the pattern to reuse —
`classifiers/find.py`'s `-exec` payload extraction follows the same shape (find the wrapped
command's tokens, gate on `APPEND_SAFE`, recurse). Both `\;` and `+` terminators share the
same gate for auditability, even though `\;` is technically the safer of the two (one
positional substitution vs. `+`'s batching).

## Extending the guard

- **Add a pure read utility** → append it to `NAMES` in `classifiers/readonly.py`.
- **Add a command that's read-only only in some forms** → create `classifiers/<cmd>.py`
  with `NAMES` + a `classify(tokens)` returning `ALLOW` for the safe form and
  `deny(reason)` otherwise, then register the module in `registry.py`'s `_MODULES`.
- **Widen `gh` reads** → edit `GH_READ` in `classifiers/gh.py`. **Widen `git` reads** →
  edit `GIT_READ` in `classifiers/git.py` (pure-read subcommands only; anything read-only
  *only in some forms* — like `config`, `tag`, `stash` — gets a dedicated branch in that
  file's `classify()`).
- After any change, add matching `ALLOW`/`DEFER` cases and run the suites (below).

**When in doubt, `deny`** (defer). Never `ALLOW` a form you cannot prove is read-only.

## Testing (required after any change)

Three stdlib-only suites, each exits 1 on any failure — run them after any edit:

```bash
python3 ~/.claude/hooks/bash-guard/test_bash_guard.py    # end-to-end (over stdin)
python3 ~/.claude/hooks/bash-guard/test_classifiers.py   # per-classifier units
python3 ~/.claude/hooks/bash-guard/test_audit.py         # audit log + auto-trim
```

- **`test_bash_guard.py`** drives the whole hook through the shim over stdin — it covers
  read-only and inspected commands, pipelines, redirects, the `#`-truncation guard, and
  the quote-phase bail-outs (`$'…'`, comments, heredocs) with their exploit payloads.
  Add a case to its `ALLOW` (must auto-approve) or `DEFER` (must fall back to a prompt)
  list whenever you extend the hook.
- **`test_classifiers.py`** calls each `classify(tokens)` directly, so a failure points
  straight at the offending command's module. Add a case here when you add or change a
  classifier's allow/deny logic.

Quick manual check — the hook reads a `PreToolUse` JSON payload on stdin and prints a
decision (or nothing) on stdout:

```bash
jq -n --arg c 'git log | grep FIX' '{tool_input:{command:$c}}' \
  | python3 ~/.claude/hooks/bash-guard/bash-guard.py
# -> {"hookSpecificOutput":{...,"permissionDecision":"allow",...}}

jq -n --arg c 'grep x f | tee out' '{tool_input:{command:$c}}' \
  | python3 ~/.claude/hooks/bash-guard/bash-guard.py
# -> (no output; exit 0 => defers to normal permission flow)
```

## Audit log

Every decision is appended to `bash-guard.log` (next to `bash-guard.py`) as one JSON
object per line — `{ts, decision, reason, command}`:

```jsonl
{"ts":"2026-08-03T14:23:08+00:00","decision":"allow","reason":"read-only command / pipeline","command":"git log | grep FIX"}
{"ts":"2026-08-03T14:23:08+00:00","decision":"defer","reason":"unknown command: rsync","command":"rsync -a a b"}
```

The point is **tuning the guard over time**: the `defer` records and their `reason` (e.g.
`unknown command: rsync`, `sed -i is in-place`) show which commands/forms are worth
teaching the guard to auto-allow. Aggregate them:

```bash
# Most-frequently-deferred commands, most common first.
jq -r 'select(.decision=="defer") | .reason' \
  ~/.claude/hooks/bash-guard/bash-guard.log | sort | uniq -c | sort -rn
```

- **Multi-line commands** stay one physical line — embedded newlines are escaped as `\n`
  inside the JSON string, so `jq` round-trips them intact.
- **Auto-trim:** logging is fail-safe (any error is swallowed — it can never break the
  shell) and the file is capped at ~1 MB; when exceeded, the oldest half is dropped in
  place on the next write. See `guard/audit.py`.
- **Override the path** with `BASH_GUARD_LOG` (used by the tests; point it at `/dev/null`
  to disable logging).
