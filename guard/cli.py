"""Orchestration: read the PreToolUse payload, decide allow vs defer.

Goal: auto-allow *read-only* shell invocations — including pipelines — while
deferring (handing the decision back to Claude Code's normal permission flow)
on anything mutating or not understood.

FAIL SAFE. A pipeline / sequence is auto-allowed only if EVERY segment is itself
read-only and there are no output redirects / command substitutions. Every
uncertainty defers; we never emit "allow" on doubt.
"""

import json
import sys
from typing import Tuple

from . import audit
from .decision import defer, emit
from .parser import strip_leading_assignments, to_segments
from .redirects import strip_redirects
from .registry import CLASSIFIERS


def main() -> None:
    # This hook runs on EVERY Bash call, so it must never crash the user's
    # shell flow. emit()/defer() raise SystemExit (a BaseException), so they pass
    # through untouched; any *other* unexpected error falls back to a normal
    # prompt — the same fail-safe posture as deferring on doubt.
    try:
        _run()
    except Exception:
        defer("guard internal error")


def evaluate(cmd: str) -> Tuple[bool, str]:
    """Read-only verdict for a full command string: ``(is_read_only, reason)``.

    This is the whole per-segment analysis with no ``sys.exit``/audit side
    effects, so ``guard/substitution.py`` can recurse into it to check a
    ``$(...)``/backtick INNER command through the exact same pipeline
    (``to_segments`` -> ``strip_redirects`` -> ``strip_leading_assignments`` ->
    ``CLASSIFIERS`` dispatch) rather than a parallel reimplementation — nested
    substitutions therefore work for free. Only ``_run()`` (the sole top-level
    caller) may turn a verdict into ``defer()``/``emit()``.
    """
    segments = to_segments(cmd)
    if segments is None:
        return False, "unparsable command (substitution/subshell/quotes)"

    saw_known_target = False
    wrote_temp = False
    for seg in segments:
        # Strip redirects. Output redirect to a real file => a write => defer.
        # A redirect to a temp path is a benign confined write (wrote_temp).
        cleaned, redir_wrote = strip_redirects(seg)
        if cleaned is None:
            return False, "redirect writes a real file"
        wrote_temp = wrote_temp or redir_wrote
        if not cleaned:
            continue
        # Drop leading `FOO=bar` env assignments so `FOO=bar grep x` classifies
        # on `grep`. A segment that is ONLY assignments (`FOO=bar`) is read-only.
        cleaned = strip_leading_assignments(cleaned)
        if not cleaned:
            saw_known_target = True
            continue
        classify = CLASSIFIERS.get(cleaned[0])
        if classify is None:
            return False, f"unknown command: {cleaned[0]}"
        ok, reason = classify(cleaned)
        if not ok:
            return False, reason
        # On an allow, a non-empty reason is an informational side-effect note
        # (e.g. tmpwrite signalling a confined temp write); see classifiers/base.
        wrote_temp = wrote_temp or bool(reason)
        saw_known_target = True

    if not saw_known_target:
        return False, "no recognized command"

    return True, ("confined temp write" if wrote_temp else "read-only command / pipeline")


def _run() -> None:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
        cmd = data.get("tool_input", {}).get("command", "")
    except Exception:
        defer("unparseable payload")
    audit.set_command(cmd if isinstance(cmd, str) else "")
    if not isinstance(cmd, str) or not cmd.strip():
        defer("empty command")

    ok, reason = evaluate(cmd)
    if not ok:
        defer(reason)
    emit("allow", reason)
