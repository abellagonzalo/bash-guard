"""Append-only audit log of every guard decision, for tuning the guard later.

One JSONL line per Bash invocation: ``{ts, decision, reason, command}``. The
high-value signal is the *deferred* commands and their reason (e.g.
``unknown command: rsync``) — aggregating those tells us which commands/forms
are worth teaching the guard to auto-allow.

FAIL SAFE: this hook runs on EVERY Bash call, so logging must never break the
shell flow. ``log()`` swallows all errors, and it writes only to the log file
(never stdout, which is reserved for ``decision.emit``'s JSON).

Multi-line commands stay a single physical line: ``json.dumps`` escapes embedded
newlines as ``\\n`` inside the string value, so one entry == one line. The
trimmer relies on that when it drops whole lines from the front.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Log next to bash-guard.py (this file is guard/audit.py -> parent.parent is the
# bash-guard/ dir). Overridable via env so tests can redirect, or you can point
# it at /dev/null to disable.
LOG_PATH = Path(
    os.environ.get(
        "BASH_GUARD_LOG",
        Path(__file__).resolve().parent.parent / "bash-guard.log",
    )
)

# Cap the log at ~1 MB; when exceeded we drop the oldest half in place.
MAX_BYTES = 1_000_000

# The command under judgement, stashed by the orchestrator (cli._run) so the
# terminal emit()/defer() can log it without threading it through every call.
_command = ""


def set_command(command: str) -> None:
    global _command
    _command = command if isinstance(command, str) else ""


def log(decision: str, reason: str) -> None:
    """Append one JSONL record for the current command. Never raises."""
    try:
        _log(decision, reason)
    except Exception:
        pass


def _log(decision: str, reason: str) -> None:
    line = json.dumps(
        {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "decision": decision,
            "reason": reason,
            "command": _command,
        },
        ensure_ascii=False,
    )
    _trim_if_needed()
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def _trim_if_needed() -> None:
    """Keep the newest half when the log grows past ``MAX_BYTES``.

    Cheap hot path: a single ``stat`` on the common (under-cap) case. When over,
    rewrite keeping the tail from the first newline boundary so no partial entry
    survives at the front.
    """
    try:
        if LOG_PATH.stat().st_size <= MAX_BYTES:
            return
    except FileNotFoundError:
        return
    data = LOG_PATH.read_bytes()
    keep = data[len(data) // 2:]
    nl = keep.find(b"\n")
    keep = keep[nl + 1:] if nl != -1 else b""
    LOG_PATH.write_bytes(keep)
