#!/usr/bin/env python3
"""Tests for the audit log (guard/audit.py).

Two parts, both stdlib-only and matching the sibling suites' exit-1-on-failure
convention:

* End-to-end: run the hook through the shim over stdin (exactly as Claude Code
  does), with the log redirected to a temp file via ``BASH_GUARD_LOG``, and
  assert the expected JSONL record is written for allow / defer / multi-line.
* Unit: drive ``audit._trim_if_needed`` past ``MAX_BYTES`` and assert it keeps
  the newest half on a clean line boundary.

    python3 tests/test_audit.py     # -> prints a summary, exits 1 on any failure
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

HOOK = str(Path(__file__).parent.parent / "bash-guard.py")

failures = []


def check(label, cond):
    print(f"[{'ok' if cond else 'FAIL'}] {label}")
    if not cond:
        failures.append(label)


def run_hook(command, log_path):
    """Run the hook with the log redirected; return the last logged record."""
    payload = json.dumps({"tool_input": {"command": command}})
    env = dict(os.environ, BASH_GUARD_LOG=str(log_path))
    subprocess.run([sys.executable, HOOK], input=payload, capture_output=True,
                   text=True, env=env)
    lines = Path(log_path).read_text(encoding="utf-8").splitlines()
    return json.loads(lines[-1]) if lines else None


def test_e2e():
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "bash-guard.log"

        rec = run_hook("git log | grep FIX", log)
        check("allow: decision", rec and rec["decision"] == "allow")
        check("allow: command round-trips", rec and rec["command"] == "git log | grep FIX")
        check("allow: has ts", rec and bool(rec.get("ts")))

        rec = run_hook("totallyunknowncmd --flag", log)
        check("defer: decision", rec and rec["decision"] == "defer")
        check("defer: reason names the command",
              rec and "unknown command: totallyunknowncmd" in rec["reason"])

        # Allow reason must be honest: confined temp writes are labeled as such,
        # while pure reads (and discards / fd-dups that write no file) stay
        # "read-only command / pipeline".
        temp_write = [
            "echo hi > /tmp/f",
            "touch /tmp/x",
            "jq . /tmp/a.json > /tmp/b",   # the log-line-3 case: a redirect write
        ]
        for cmd in temp_write:
            rec = run_hook(cmd, log)
            check(f"temp-write: allow <- {cmd!r}", rec and rec["decision"] == "allow")
            check(f"temp-write: reason <- {cmd!r}",
                  rec and rec["reason"] == "confined temp write")

        read_only = [
            "cat a | sort | uniq -c",      # pure read pipeline
            "grep x f 2>/dev/null",        # discard, not a write
            "grep x f 2>&1",               # fd duplication, not a write
        ]
        for cmd in read_only:
            rec = run_hook(cmd, log)
            check(f"read-only: allow <- {cmd!r}", rec and rec["decision"] == "allow")
            check(f"read-only: reason <- {cmd!r}",
                  rec and rec["reason"] == "read-only command / pipeline")

        # A multi-line command must occupy exactly ONE physical line and
        # round-trip back to the original string.
        multiline = "for f in *; do\n  rm $f\ndone"
        before = len(log.read_text(encoding="utf-8").splitlines())
        rec = run_hook(multiline, log)
        after = len(log.read_text(encoding="utf-8").splitlines())
        check("multiline: single physical line added", after - before == 1)
        check("multiline: command round-trips", rec and rec["command"] == multiline)


def test_trim():
    import guard.audit as audit

    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "bash-guard.log"
        orig_path, orig_max = audit.LOG_PATH, audit.MAX_BYTES
        audit.LOG_PATH, audit.MAX_BYTES = log, 2_000
        try:
            audit.set_command("x")
            for i in range(500):
                audit.log("defer", f"reason {i}")
            data = log.read_bytes()
            check("trim: capped at MAX_BYTES", len(data) <= audit.MAX_BYTES)
            check("trim: starts on a clean line (no partial entry)",
                  data == b"" or json.loads(data.splitlines()[0]))
            last = json.loads(data.splitlines()[-1])
            check("trim: keeps the newest entry", last["reason"] == "reason 499")
        finally:
            audit.LOG_PATH, audit.MAX_BYTES = orig_path, orig_max


def main():
    test_e2e()
    test_trim()
    print()
    if failures:
        print(f"{len(failures)} FAILED: " + ", ".join(failures))
        return 1
    print("All audit cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
