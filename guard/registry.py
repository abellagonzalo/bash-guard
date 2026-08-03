"""Command name -> classifier dispatch table.

Folds every module's ``NAMES`` onto its ``classify``. Membership in
``CLASSIFIERS`` is also what "we recognize this command" means for the
orchestrator's ``saw_known_target`` check.

To register a new command, drop a module in ``classifiers/`` (exposing ``NAMES``
+ ``classify``) and add it to ``_MODULES`` below. Pure read utilities need only
an entry in ``classifiers/readonly.py``'s ``NAMES``.
"""

from .classifiers import (
    awk, command, curl, date, env, find, gh, git, readonly, sed, sort, tmpwrite,
    yq,
)

_MODULES = (
    readonly, find, sed, awk, gh, git, env, command, curl, date, tmpwrite,
    sort, yq,
)

CLASSIFIERS = {}
for _mod in _MODULES:
    for _name in _mod.NAMES:
        # A name claimed by two modules would silently let the last-registered
        # one win — almost always a copy-paste mistake. Fail loudly at import.
        if _name in CLASSIFIERS:
            raise RuntimeError(
                f"duplicate classifier registration for {_name!r} "
                f"(check NAMES in classifiers/)"
            )
        CLASSIFIERS[_name] = _mod.classify
