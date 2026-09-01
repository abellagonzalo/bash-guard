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
│   ├── substitution.py      # $(...)/backtick: recurse into the inner command, replace with a placeholder
│   ├── quoting.py           # shared '...'/"..."/$'...' span-skip primitives (used by parser.py + substitution.py)
│   ├── redirects.py         # redirect operators + strip_redirects()
│   ├── paths.py             # is_tmp_path(): temp-dir write predicate
│   ├── registry.py          # command name -> classifier dispatch table + APPEND_SAFE map (built at import)
│   └── classifiers/
│       ├── base.py          # ALLOW / deny() result contract
│       ├── subcommand.py    # find_subcommand(): shared global-flags-then-subcommand walk
│       ├── readonly.py      # pure read utilities (NAMES)
│       ├── tmpwrite.py      # writes confined to a temp dir (touch/mkdir/tee/rm/mv/cp)
│       ├── xargs.py         # recurses into an append-safe wrapped command
│       └── find.py, sed.py, sort.py, yq.py, awk.py, git.py, gh.py, curl.py, env.py, command.py, date.py, docker.py, kubectl.py
└── test_bash_guard.py, test_classifiers.py, test_audit.py, test_substitution.py
```

Each `classifiers/*.py` module exposes `NAMES` (the command names it handles) and
`classify(tokens) -> (ok, reason)`. `registry.py` folds every module's `NAMES` onto its
`classify`; membership in that map is also what "we recognize this command" means. The
registry is **fail-loud**: two modules claiming the same name in `NAMES` raise at import
(`duplicate classifier registration`). `main()` wraps its work so any *unexpected* error
defers rather than crashing — this hook runs on every Bash call, so it must never break
the shell flow.

`cli.py`'s per-segment analysis lives in a pure function, `evaluate(cmd) -> (ok, reason)`,
with no `sys.exit`/audit side effects — `_run()` is a thin wrapper around it. This exists so
`guard/substitution.py` can recurse into it to check a `$(...)`/backtick INNER command
through the exact same pipeline, not a parallel reimplementation.

## How a command is judged

1. **Bail-outs → defer.** Process substitution (`<(…)`, `>(…)`), *unquoted* subshell
   grouping `( … )`, ANSI-C quoting (`$'…'`), output redirects to a real file (`>`, `>>`,
   and the combined `>&file` / `&>file` / `&>>file` forms), `<>` read-write opens, and
   unbalanced quotes are never auto-approved. Redirects that only **discard**,
   **duplicate** a descriptor, or **write into a temp dir** are harmless and do not block
   auto-approval: `>/dev/null`, `2>/dev/null`, fd duplications `2>&1` / `>&2`, and writes
   confined to a temp dir — `>/tmp/out`, `2>/tmp/err`, `>>/private/tmp/log`, `>$TMPDIR/f`
   (see `guard/paths.py`). Command substitution (`$(…)`, backticks) is **not** an
   unconditional bail-out — see the callout below.

   > ⚠️ **Command substitution (`$(…)`/backtick) recurses instead of deferring
   > outright** (`guard/substitution.py`, issue #4). Bash lets `$(...)`/backtick expand
   > both unquoted and inside `"…"` (but not inside `'…'` or `$'…'`, which suppress all
   > expansion), so `desubstitute()` walks the raw command with that same quote-awareness
   > (via the shared `quoting.py` primitives — see below), and for each span found:
   > extracts the inner text, recursively runs it through `cli.evaluate()` (the exact same
   > segment/classifier pipeline as the outer command, so an inner pipeline, redirects, or
   > its own nested substitutions "just work"), and — only if the inner command is
   > provably read-only — replaces the WHOLE span with a fixed, metacharacter-free
   > placeholder (`__BASHGUARD_SUBST__`) before the outer command continues through the
   > ordinary `to_segments`/`shlex` pipeline. An unterminated span or a non-read-only inner
   > command defers the whole outer command, same as any other bail-out.
   >
   > The closing `)` of a `$(...)` is found with a quote-aware **paren-depth counter**
   > (starts at 1, `(` increments, `)` decrements, quoted regions are skipped atomically) —
   > this is exactly how bash's own parser finds the match, and it handles a nested
   > `$(...)` "for free": its own parens are just more depth to the same counter, never
   > special-cased. `$((...))` arithmetic expansion isn't special-cased either — it reads as
   > `$(` with inner text `(expr)`, which fails the bare-paren bail-out below when that's
   > recursively parsed, so it always defers (no classifier understands arithmetic).
   >
   > Backticks don't nest, so their matching close is just "the next unescaped backtick" —
   > deliberately **not** quote-aware inside the span. A literal backtick inside a nested
   > quote is misread as the terminator, but the truncated remainder then almost always
   > contains an unbalanced quote, which the unterminated-quote fail-safes below (or
   > `shlex`'s own `ValueError`) catch — a safe failure direction (extra defer), never a
   > false allow.
   >
   > Process substitution (`<(…)`, `>(…)`) stays a **flat, unconditional** defer, checked
   > *before* `desubstitute()` runs, regardless of quoting — deliberately out of scope
   > (different semantics: it yields a `/dev/fd` path, not text).
   >
   > Once a `$(...)` is proven read-only, treating its stdout as an opaque runtime value is
   > no riskier than this tool's existing, unguarded acceptance of an unquoted `$VAR`
   > expansion (never bailed out on): the actual safety net in both cases is that
   > classifiers do strict token-shape matching and fail closed on anything unexpected.

   > ⚠️ **Subshell detection reads the RAW string, not the tokens.** `shlex` resolves
   > escapes before we see a token, so `\(` (a literal `find` operand) and a real subshell
   > `(` both lex to `(`. `guard/parser.py`'s `_needs_raw_bailout()` therefore walks the
   > raw command tracking bash's quoting forms (`\c`, `'…'` where a backslash is *not* an
   > escape, `"…"` where it is) and defers only on a paren that is genuinely unquoted and
   > unescaped. So `find . \( -name "*.kt" -o -name "*.yml" \)` and `find . '(' … ')'` are
   > auto-approved, while `(cd /tmp && ls)`, `f() { … }`, and `case x in a) …` still defer.
   > An unterminated quote returns "unquoted" so ambiguity always defers. The `'…'`/`"…"`
   > span-skip logic is shared (`guard/quoting.py`'s `skip_single`/`skip_double`, plus
   > `skip_ansi_c` for `$'…'`) rather than reimplemented per caller — this repo has twice
   > shipped a bug (issues behind commits `4e1c601`, `49e580d`) from two independent quote
   > walks drifting subtly out of sync, and `substitution.py`'s span finder is a third
   > caller of the same primitives.
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
   > ⚠️ **The same walk bails out on a word-start `#`.** Bash treats a comment body as
   > *inert*; neither this walk nor shlex (with `commenters = ""`) does. An odd quote count
   > in such a region shifts the quote phase and a second one shifts it back, so both sides
   > end balanced, no fail-safe fires, and a later **real** command is swallowed as the
   > contents of a string — `echo hi # don't` / newline / `rm -rf ~ # it's` was
   > auto-approved (issue #8). Two subtleties: the `#` test is scoped to a **word start**
   > (start of string, or after unquoted whitespace or one of `;|&<>()`) so a mid-token `#`
   > still lexes and `commenters = ""` keeps its meaning; and `\` + newline is line
   > continuation, so the character *before* the backslash decides the word start —
   > otherwise `echo hi \` / newline / `# don't` hides the same payload. Free in practice:
   > of the 1123 unique auto-allowed commands in the audit log, none carries a word-start
   > `#` (the one that matches a naive grep is inside `"…"`).
   >
   > ⚠️ **A heredoc body is the same class of hazard, but resolved in an earlier, separate
   > pass — `guard/parser.py`'s `_strip_quoted_heredocs()`, run *first* in `to_segments`,
   > before `substitution.desubstitute()` and `_needs_raw_bailout()` ever see the string.**
   > A quoted-delimiter heredoc (`<<'EOF'`/`<<"EOF"`, no `<<-`) gets a hard guarantee from
   > bash itself: the body has **zero expansion** — no `$var`, no backticks, no further
   > quote processing — so there's nothing live left to quote-desync on, once the body is
   > located structurally rather than scanned. `_consume_quoted_heredoc()` requires the
   > delimiter to be a plain identifier (`[A-Za-z_][A-Za-z0-9_]*`, no `$`, no embedded
   > whitespace) immediately followed by whitespace/newline/end-of-string (else bash would
   > concatenate it with adjacent unquoted text into a different, longer delimiter — e.g.
   > `<<'EOF'x` really terminates on `EOFx`, not `EOF`), finds a line that is *exactly* that
   > delimiter (no leading/trailing characters, since `<<-` is excluded), and drops the
   > newline-through-delimiter-line span from the string, leaving the `<<'EOF'` operator
   > itself untouched for `shlex`/`strip_redirects` (`REDIR_IN` already lists `"<<"`) to
   > tokenize normally. Any `<<` outside this narrow scope — unquoted delimiter, `<<-`,
   > `<<<`, unterminated, non-identifier delimiter, no matching terminator line — bails out
   > the WHOLE command, the same blanket `<<` defer this hook always had (issue #16).
   >
   > This has to run BEFORE `desubstitute()`, not folded into the `#`/paren walk above:
   > `desubstitute()` has its own, independent quote-tracking walk with no heredoc
   > awareness. An earlier version stripped heredoc bodies too late (in the `#`/paren walk,
   > which already runs after `desubstitute()`), so `desubstitute()` still saw an
   > unstripped body first — `cat <<'EOF'\nit's\nEOF` has a genuine apostrophe in its
   > (inert) body, and `desubstitute()` read it as a real quote-open, hunted for a closing
   > `'` that was never coming, and deferred a command that should auto-allow. Exactly the
   > "two independent quote walks drift out of sync" bug class this file's `quoting.py`
   > section warns about — stripping heredoc bodies first, before ANY other pass looks at
   > the string, is what keeps every later pass from ever needing to be heredoc-aware.

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
3. **Split** into segments on `|`, `||`, `&&`, `;`, `&`, and a bare newline.

   > ⚠️ **A bare newline is a separator too — this was a real false-allow.** `shlex`'s
   > `whitespace_split=True` treats `\n` as ordinary whitespace, not a control operator, so
   > without special-casing it a two-line command with no `;`/`&&` between the lines —
   > e.g. `cd /tmp` / newline / `rm -rf ~/x` — collapsed into ONE segment classified only
   > on its first word. Any classifier that ignores its own arguments (`cat`, `echo`, `ls`,
   > `cd`, … — `classifiers/readonly.py`'s `APPEND_SAFE` list) then auto-allowed the whole
   > thing, silently swallowing the second, completely unrelated, unvetted statement as
   > bogus trailing "arguments" of the first — verified live against real multi-line
   > agent-issued commands. `_protect_escaped_semicolons()` (renamed in spirit, not in
   > code) now converts every bare, unquoted, unescaped `\n` to a literal `;` before
   > lexing, using the same quote-skip walk as the `\;` handling below. A `\` + newline is
   > a genuine line continuation, not a separator — bash deletes the pair and joins the
   > lines with nothing in between — so that one case is deleted outright rather than
   > turned into a `;`.

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
| `git` | read subcommand (`status`, `log`, `diff`, `show`, `branch`, `blame`, `remote`, `rev-parse`, `ls-*`, `merge-base`, `check-ignore`, `git grep`, …); `config --get/--list`; `tag`/`tag -l`; `stash list/show`; `worktree list`; `submodule status/summary` | writes, `git tag <name>`, `config` set/`--unset`, `stash`/`worktree add`/`submodule update`, or **any** global flag other than `--version`/`--help`/`-h` — an unrecognized one (e.g. `-c`/`-C`/`--exec-path`/`--git-dir`/`--work-tree`) fails safe via `find_subcommand()` rather than being guessed as boolean-and-skipped (issue #17) |
| `gh api` | GET (no method/body flags) | `-X/--method POST\|PUT\|PATCH\|DELETE`, `-f/-F/--field/--raw-field/--input` |
| `gh` (other) | read subcommand (`pr view/list/diff/checks/status`, `run view/list`, `issue`, `repo view/list`, `auth status`, `gist list/view`, …) | any other subcommand (`pr create`, `pr merge`, …) |
| `curl` | GET/HEAD only, no request body/upload, response written only to a temp dir | non-GET verb (`-X POST`), body/upload flags (`-d`/`--data`/`-F`/`-T`/`--json`), output outside a temp dir (`-o`/`-O`), config files (`-K`), or a dangerous letter hidden in a short-flag bundle |
| `psql` | only `-h`/`-p`/`-U`/`-d`/`-x` (+ long forms) plus bare connection-info positionals; a `-c`/`--command` value that is a single `SELECT` (no `INTO`) or a safe meta-command (`\d*`, `\l`, `\z`, `\x`, `\timing`, `\conninfo`, `\?`, `\h`) | `-f`/`--file`, any flag outside that allowlist (incl. an ambiguous bundle like `-xc`), a `-c` value with more than one statement or an embedded newline, `SELECT … INTO`, or an unsafe meta-command (`\copy`, `\i`, `\o`, `\g`, `\w`, `\e`, `\!`, `\set`, …) |
| `env` | bare, or only `NAME=VALUE` assignments | any bare operand (it would *run* that command), unknown options |
| `command` | `command -v/-V NAME` (lookup) | `command NAME …` (it *runs* NAME) |
| `date` | reading/formatting | `-s` / `--set` (sets the system clock) |
| `docker` | read subcommand (`ps`, `images`, `info`, `inspect`, `logs`, `version`, `top`, `stats`, `diff`); `context ls/list/show/inspect`; `compose ps/logs/config/images/ls/top/port/version` | `exec`, `run`, `rm`, `stop`, `kill`, `start`, `compose up/down/exec/rm`, any other subcommand, or **any** global flag other than `--version`/`-v`/`--help` (e.g. `-H`/`--context`) — same fail-safe `find_subcommand()` rule as `git` (issue #17) |
| `kubectl` | read verb (`get`, `describe`, `logs`, `version`, `explain`, `top`, `api-resources`, `api-versions`) optionally preceded by known value-taking global flags (`-n`/`--namespace`, `--context`, `--cluster`, `--kubeconfig`, `--as`, `--as-group`, `--token`, `--server`, `--user`, `--client-certificate`, `--client-key`, `--certificate-authority`, `--cache-dir` — `KUBECTL_VALUE_FLAGS`, not exhaustive of every real kubectl global flag); `config current-context/view/get-contexts/get-clusters/get-users` | `exec`, `apply`, `delete`, `edit`, `patch`, `cp`, `port-forward`, any other subcommand, or an unrecognized global flag (fails safe via `find_subcommand()` rather than being guessed as boolean, issue #17) |
| `touch` `mkdir` `tee` `rm` `mv` | every operand is a temp path (`/tmp/…`, `/private/tmp/…`, `$TMPDIR/…`) | any operand outside a temp dir, or a `..` escape |
| `cp` | destination (last operand) is a temp path; sources may be anywhere (read-only) | destination outside a temp dir, or any non-arg-less flag (e.g. `-t` / `--target-directory`) |
| `xargs` | wraps a recognized, **append-safe** command whose own classifier allows the visible tokens | unrecognized/replace-string (`-I`/`-i`/`-J`/`--replace`) flags, no wrapped command, or the wrapped command is unknown, not append-safe, or itself denies |
| `bash` | literal `-c '<script>'`, or a bare path resolving (via `realpath`, following symlinks) to a real file under a trusted root (`~/.claude/`) — either way the script text recursively classifies as read-only (trailing operands become opaque positional args, `$1`/`$2`/…; a leading shebang line is stripped before recursing) | any other flag/ordering, no `-c` and no trusted path, a relative path, or a path outside the trusted root (issue #26, follow-up to #13) |

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

Four stdlib-only suites, each exits 1 on any failure — run them after any edit:

```bash
python3 ~/.claude/hooks/bash-guard/test_bash_guard.py    # end-to-end (over stdin)
python3 ~/.claude/hooks/bash-guard/test_classifiers.py   # per-classifier units
python3 ~/.claude/hooks/bash-guard/test_audit.py         # audit log + auto-trim
python3 ~/.claude/hooks/bash-guard/test_substitution.py  # desubstitute() + quoting.py units
```

- **`test_bash_guard.py`** drives the whole hook through the shim over stdin — it covers
  read-only and inspected commands, pipelines, redirects, the `#`-truncation guard, and
  the quote-phase bail-outs (`$'…'`, comments, heredocs) with their exploit payloads.
  Add a case to its `ALLOW` (must auto-approve) or `DEFER` (must fall back to a prompt)
  list whenever you extend the hook.
- **`test_classifiers.py`** calls each `classify(tokens)` directly, so a failure points
  straight at the offending command's module. Add a case here when you add or change a
  classifier's allow/deny logic.
- **`test_substitution.py`** calls `desubstitute()` and the `guard/quoting.py` span-skip
  primitives directly against exact expected strings/indices — catches off-by-one/index
  bugs the end-to-end suite can't localize. Add a case here when you touch
  `guard/substitution.py` or `guard/quoting.py`.

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
