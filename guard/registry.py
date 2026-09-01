"""Command name -> classifier dispatch table.

Folds every module's ``NAMES`` onto its ``classify``. Membership in
``CLASSIFIERS`` is also what "we recognize this command" means for the
orchestrator's ``saw_known_target`` check.

Also exposes ``APPEND_SAFE``, a name -> bool map for classifiers (``xargs``,
and any future ``find -exec ... {} +``-style construct) that recurse into a
wrapped command: it tells them whether the wrapped classifier's ALLOW verdict
is immune to operands appended after the visible ones. A module opts in with
a module-level ``APPEND_SAFE = True`` (see e.g. ``classifiers/readonly.py``);
absent means ``False``. See ``classifiers/wrapped.py`` for the recursion.

To register a new command, drop a module in ``classifiers/`` (exposing ``NAMES``
+ ``classify``) and add it to ``_MODULES`` below. Pure read utilities need only
an entry in ``classifiers/readonly.py``'s ``NAMES``.
"""

from .classifiers import (
    awk, bash, command, curl, date, docker, env, find, gh, git, kubectl,
    psql, readonly, sed, sort, tmpwrite, xargs, yq,
)

_MODULES = (
    readonly, find, sed, awk, gh, git, env, command, curl, date, tmpwrite,
    xargs, sort, yq, docker, kubectl, psql, bash,
)

CLASSIFIERS = {}
APPEND_SAFE = {}
for _mod in _MODULES:
    _safe = getattr(_mod, "APPEND_SAFE", False)
    for _name in _mod.NAMES:
        # A name claimed by two modules would silently let the last-registered
        # one win — almost always a copy-paste mistake. Fail loudly at import.
        if _name in CLASSIFIERS:
            raise RuntimeError(
                f"duplicate classifier registration for {_name!r} "
                f"(check NAMES in classifiers/)"
            )
        CLASSIFIERS[_name] = _mod.classify
        APPEND_SAFE[_name] = _safe
