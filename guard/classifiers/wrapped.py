"""Shared recursive dispatch into a wrapped command's classifier.

`find -exec CMD ... ;`/`find -exec CMD ... +` and `xargs CMD ...` both need
to recurse into an arbitrary wrapped command's classifier -- but only when
that command is registered as APPEND_SAFE (see guard/registry.py): a
classifier that reasons about operand POSITION could be fooled by find/xargs
appending more operands after the visible payload at runtime. This module is
the single place that performs the lookup + gate + recurse, so the two
callers can't drift apart on the exact conditions or deny-reason wording.
"""

from .base import deny


def classify_wrapped(payload, *, context):
    """payload: tokens of the wrapped command (e.g. ['rm', '/tmp/x']).
    context: short label used in deny reasons (e.g. 'find -exec', 'xargs').

    Looks up the wrapped command's classifier, requires it to be
    APPEND_SAFE, and returns its verdict -- or a deny() if the wrapped
    command is missing, unknown, or not append-safe.
    """
    # Lazy import: registry.py imports find.py/xargs.py (which import this
    # module) BEFORE it finishes building CLASSIFIERS/APPEND_SAFE, so a
    # top-level `from ..registry import ...` here would raise ImportError on
    # a partially-initialized module. classify_wrapped() only runs
    # per-request, long after registry.py has finished executing at process
    # startup, so by then the import is just a plain attribute lookup.
    from ..registry import APPEND_SAFE, CLASSIFIERS

    if not payload:
        return deny(f"{context} with no wrapped command")

    wrapped_cmd = payload[0]
    wrapped_classify = CLASSIFIERS.get(wrapped_cmd)
    if wrapped_classify is None:
        return deny(f"{context} wraps unknown command: {wrapped_cmd}")
    if not APPEND_SAFE.get(wrapped_cmd, False):
        return deny(
            f"{context} wraps a command whose classifier isn't "
            f"append-safe: {wrapped_cmd}"
        )
    return wrapped_classify(payload)
