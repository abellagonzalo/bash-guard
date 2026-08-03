"""Per-command read-only classifiers.

Each command module exposes:

* ``NAMES`` — the command names it handles (a tuple).
* ``classify(tokens)`` — returns ``ALLOW`` when that single segment is provably
  read-only, or ``deny(reason)`` otherwise.

The registry (``guard.registry``) folds every module's ``NAMES`` onto its
``classify`` to build the dispatch table.
"""
