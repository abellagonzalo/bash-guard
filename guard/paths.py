"""Predicate: does a token name a path confined to a temp directory?

Single source of truth for "this write lands under a temp dir" — used by the
redirect logic (``redirects.py``) and the write-command classifier
(``classifiers/tmpwrite.py``). Writes confined here are auto-approved.

FAIL SAFE: only returns True when the token is provably under an allowed temp
root with no traversal. Anything else is False, so the caller defers.
"""

from typing import Optional

# Allowed temp roots. On macOS ``/tmp`` resolves to ``/private/tmp``. ``$TMPDIR``
# is matched as a LITERAL token: ``shlex(posix=True)`` does not expand variables,
# so ``$TMPDIR/foo`` arrives verbatim.
_TMP_ROOTS = ("/tmp", "/private/tmp", "$TMPDIR")


def is_tmp_path(token: Optional[str]) -> bool:
    """True if ``token`` is a temp root itself or a path under one, with no
    ``..`` component that could escape it (e.g. ``/tmp/../etc/passwd``)."""
    if not token:
        return False
    if ".." in token.split("/"):
        return False
    return any(token == root or token.startswith(root + "/") for root in _TMP_ROOTS)
