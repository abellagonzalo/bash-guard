"""Hook decision output.

The hook has exactly two outcomes:

* ``emit("allow", ...)`` — the command is fully parsed and proven read-only.
* ``defer()`` — exit 0 with no output, handing the decision back to Claude
  Code's normal permission flow (deny/ask/allow rules, else prompt).

It never emits "ask"/"deny": a hook JSON "ask"/"deny" does NOT reliably override
a settings ``allow`` rule (only exit code 2 does), so it would give no
guaranteed safety benefit while risking spurious prompts for allow-listed
commands. Deferring is strictly safe.
"""

import json
import sys

from . import audit


def emit(decision: str, reason: str) -> None:
    audit.log(decision, reason)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def defer(reason: str = "unspecified") -> None:
    # Exit 0, no output => normal permission flow (deny/ask/allow rules) applies.
    # The reason is recorded only in the audit log (see guard/audit.py); it is
    # the key signal for improving the guard, since defers are what we might
    # later teach it to auto-allow.
    audit.log("defer", reason)
    sys.exit(0)
