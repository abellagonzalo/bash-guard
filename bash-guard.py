#!/usr/bin/env python3
"""PreToolUse guard for the Bash tool — entrypoint shim.

Auto-approves provably read-only shell invocations (including pipelines) and
defers everything else to Claude Code's normal permission flow. The logic lives
in the ``guard`` package alongside this file; see ``guard/`` and README.md.

This file stays the path ``~/.claude/settings.json`` points at, so the hook
wiring never has to change. Python puts this script's own directory on
``sys.path[0]``, so ``import guard`` resolves with no install step.
"""

from guard.cli import main

if __name__ == "__main__":
    main()
