<!--
*** Thanks for checking out bash-guard. README structure based on the
*** Best-README-Template by othneildrew: https://github.com/othneildrew/Best-README-Template
-->

<!-- PROJECT SHIELDS -->
[![MIT License][license-shield]][license-url]
[![Last Commit][last-commit-shield]][repo-url]
[![Issues][issues-shield]][issues-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <h1 align="center">bash-guard</h1>

  <p align="center">
    A fail-safe Claude Code hook that auto-approves provably read-only Bash commands — so safe reads run without a permission prompt.
    <br />
    <a href="./AGENTS.md"><strong>Explore the internals (AGENTS.md) »</strong></a>
    <br />
    <br />
    <a href="https://github.com/abellagonzalo/bash-guard/issues">Report Bug</a>
    &middot;
    <a href="https://github.com/abellagonzalo/bash-guard/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

`bash-guard` is a Claude Code `PreToolUse` hook (matcher: `Bash`) that **auto-approves
provably read-only shell commands — including pipelines** — so they run without a
permission prompt. It's the single source of truth for read-only `Bash` access: no
`Bash(...)` entries in `settings.json` are needed.

Its defining property is that it can **only ever add auto-approval, never take it away**.
The hook has exactly two outcomes:

* **`allow`** — the command is fully parsed and proven read-only.
* **defer** (exit 0, no output) — hand the decision back to Claude Code's normal
  permission flow (`deny` → `ask` → `allow` rules, else prompt).

It never emits `ask` or `deny`, so it is **incapable of blocking a command or introducing
a security hole**. The worst it can do is fail to auto-approve something, which simply
falls back to a normal prompt. Every decision it makes is appended to an audit log you can
mine to teach the guard about new commands over time.

Commands are tokenized with `shlex`, split into pipeline segments, and classified by a
registry of per-command modules — pure read utilities are allowed outright, while commands
that are read-only only in certain forms (`git`, `gh`, `sed`, `find`, `curl`, …) have
their arguments inspected. The full algorithm and classifier reference live in
[`AGENTS.md`](./AGENTS.md).

### Built With

* [![Python][python-shield]][python-url] — pure standard library, no dependencies
* [![Claude Code][claude-shield]][claude-url] Hooks (`PreToolUse`)

<!-- GETTING STARTED -->
## Getting Started

`bash-guard` is a single self-contained Python package invoked by Claude Code. There is
nothing to build and nothing to install beyond Python itself.

### Prerequisites

* **Python 3** (uses only the standard library — `json`, `shlex`, `re`, `pathlib`, …).
* **Claude Code** with hooks support.

### Installation

1. Clone the repo.
   ```sh
   git clone git@github.com:abellagonzalo/bash-guard.git
   ```
2. Register it as a `PreToolUse` hook in `~/.claude/settings.json`, pointing at the
   `bash-guard.py` shim (use the absolute path to your clone):
   ```json
   "hooks": {
     "PreToolUse": [
       {
         "matcher": "Bash",
         "hooks": [
           { "type": "command", "command": "/absolute/path/to/bash-guard/bash-guard.py" }
         ]
       }
     ]
   }
   ```
3. That's it — read-only Bash commands now run without a prompt. If the hook is ever
   removed, disabled, or its path changes, read-only Bash commands simply go back to
   prompting; nothing breaks.

<!-- USAGE EXAMPLES -->
## Usage

Once wired up, the guard runs automatically on every Bash tool call. You can also exercise
it by hand — it reads a `PreToolUse` JSON payload on stdin and prints a decision (or
nothing) on stdout:

```sh
# Read-only pipeline -> auto-approved
jq -n --arg c 'git log | grep FIX' '{tool_input:{command:$c}}' \
  | python3 ./bash-guard.py
# -> {"hookSpecificOutput":{...,"permissionDecision":"allow",...}}

# Writes a file -> deferred to the normal permission flow
jq -n --arg c 'grep x f | tee out' '{tool_input:{command:$c}}' \
  | python3 ./bash-guard.py
# -> (no output; exit 0 => defers)
```

Every decision is appended to `bash-guard.log` (JSONL). Mine the deferrals to see which
commands are worth teaching the guard to auto-allow:

```sh
jq -r 'select(.decision=="defer") | .reason' bash-guard.log | sort | uniq -c | sort -rn
```

_For the full command-judging algorithm, the classifier reference table, and how to add or
widen classifiers, see [`AGENTS.md`](./AGENTS.md)._

<!-- ROADMAP -->
## Roadmap

- [ ] Broaden read-only coverage for `git` (`GIT_READ`) and `gh` (`GH_READ`) subcommands.
- [ ] Add classifiers for more commonly-deferred tools surfaced by the audit log.
- [ ] Optional per-project overrides for the temp-dir write allowlist.

See the [open issues](https://github.com/abellagonzalo/bash-guard/issues) for a full list
of proposed features and known issues.

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open-source community such an amazing place to learn and
create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/amazing-feature`)
3. Make your change (start from the [Extending the guard](./AGENTS.md#extending-the-guard)
   section of `AGENTS.md`)
4. **Add matching `ALLOW`/`DEFER` test cases and run the suites** — they must pass:
   ```sh
   python3 tests/run_all.py
   ```
   Individual suites can still be run directly to pinpoint a failure, e.g.
   `python3 tests/test_bash_guard.py` or `python3 tests/classifiers/test_git.py`.
   Also run `mypy` (requires `pip3 install mypy`) — `guard/` is fully type-hinted:
   ```sh
   python3 -m mypy
   ```
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

> **Golden rule:** the guard's safety rests on never `allow`-ing something it hasn't proven
> read-only. **When in doubt, defer.**

<!-- LICENSE -->
## License

Distributed under the MIT License. See [`LICENSE`](./LICENSE) for more information.

<!-- CONTACT -->
## Contact

Gonzalo Abella — [@abellagonzalo](https://github.com/abellagonzalo)

Project Link: [https://github.com/abellagonzalo/bash-guard](https://github.com/abellagonzalo/bash-guard)

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
* [Claude Code Hooks documentation](https://docs.claude.com/en/docs/claude-code/hooks)

<!-- MARKDOWN LINKS & IMAGES -->
[license-shield]: https://img.shields.io/github/license/abellagonzalo/bash-guard.svg?style=for-the-badge
[license-url]: ./LICENSE
[last-commit-shield]: https://img.shields.io/github/last-commit/abellagonzalo/bash-guard.svg?style=for-the-badge
[issues-shield]: https://img.shields.io/github/issues/abellagonzalo/bash-guard.svg?style=for-the-badge
[issues-url]: https://github.com/abellagonzalo/bash-guard/issues
[repo-url]: https://github.com/abellagonzalo/bash-guard
[python-shield]: https://img.shields.io/badge/Python_3-3776AB?style=for-the-badge&logo=python&logoColor=white
[python-url]: https://www.python.org/
[claude-shield]: https://img.shields.io/badge/Claude_Code-D97757?style=for-the-badge&logo=anthropic&logoColor=white
[claude-url]: https://docs.claude.com/en/docs/claude-code/overview
