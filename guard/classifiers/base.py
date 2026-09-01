"""Shared classifier result contract.

A classifier returns a ``(is_read_only, reason)`` tuple. Use ``ALLOW`` for the
proven-read-only case and ``deny(reason)`` otherwise. When in doubt, ``deny`` —
the hook's safety rests on never allowing something it hasn't proven read-only.

On an *allow* result, a non-empty ``reason`` is an informational note about a
benign side effect (e.g. a confined temp write; see ``classifiers/tmpwrite.py``)
that the orchestrator uses to label the decision honestly. An empty reason means
a pure read.
"""

from typing import NamedTuple


class Result(NamedTuple):
    ok: bool
    reason: str


ALLOW = Result(True, "")


def deny(reason: str) -> Result:
    return Result(False, reason)
