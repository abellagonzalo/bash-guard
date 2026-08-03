"""Redirect operator constants and per-segment redirect stripping.

Operator tokens are produced by ``shlex(punctuation_chars=...)``. Punctuation
runs collapse into one token, so ``2>&1`` lexes as ``2``, ``>&``, ``1`` and the
combined redirect operators below must be matched explicitly — a bare ``>``/``<``
check would miss ``>&file`` / ``&>file``, which write a real file.
"""

import re

from .paths import is_tmp_path

REDIR_OUT = {">", ">>"}
REDIR_IN = {"<", "<<", "<<<"}
REDIR_MERGE = {">&", "&>", "&>>", ">>&"}  # stdout(+stderr) -> fd OR file
REDIR_RW = {"<>"}                          # opens for read+write -> treat as write
REDIR_INDUP = {"<&"}                        # input fd duplication -> read-only


def strip_redirects(seg):
    """Remove redirects from one segment.

    Returns a ``(cleaned, wrote_temp)`` tuple. On success ``cleaned`` is the
    token list with redirects removed and ``wrote_temp`` is ``True`` iff an
    output redirect targeted a path under a temp dir (a benign, confined write
    the caller still auto-approves but should label honestly). When the segment
    contains a redirect that writes a *real* file, ``cleaned`` is ``None`` (a
    write => the caller must defer); ``wrote_temp`` is ``False`` in that case.

    ``/dev/null`` discards and ``>&``/``&>`` fd duplications are NOT writes, so
    they leave ``wrote_temp`` unset. Input redirects are read-only: their target
    token is dropped so it isn't mistaken for a command.
    """
    cleaned = []
    wrote_temp = False
    skip_next = False
    for j, t in enumerate(seg):
        if skip_next:
            skip_next = False
            continue
        if t in REDIR_OUT or t in REDIR_MERGE:
            target = seg[j + 1] if j + 1 < len(seg) else None
            # Harmless targets:
            #   * /dev/null            -> discard (`>/dev/null`, `2>/dev/null`)
            #   * a path under a temp dir -> a confined write we auto-approve
            #     (`>/tmp/out`, `2>/tmp/err`); see guard/paths.py.
            #   * a bare fd number, but ONLY for the `>&`/`&>` merge forms
            #     (`2>&1`, `>&2`) which duplicate a descriptor. For a plain
            #     `>`, a numeric target is a FILE named e.g. "2" -> a write.
            fd_dup = t in REDIR_MERGE and target is not None \
                and re.fullmatch(r"\d+", target)
            if target == "/dev/null" or fd_dup or is_tmp_path(target):
                # A temp-path target is a real (if confined) file write; flag it
                # so the caller can label the decision honestly. /dev/null and
                # fd-dups write no file, so they leave wrote_temp untouched.
                if target != "/dev/null" and not fd_dup:
                    wrote_temp = True
                # Drop a preceding source fd we already appended (the `2` in
                # `2>&1` / `2>/dev/null`) and skip the target token.
                if cleaned and re.fullmatch(r"\d+", cleaned[-1]):
                    cleaned.pop()
                skip_next = True
                continue
            return None, False  # redirect to a real file => a write
        if t in REDIR_RW:
            return None, False  # `<>` can write to the file too
        if t in REDIR_IN or t in REDIR_INDUP:
            skip_next = True  # read-only; drop the redirect target token
            continue
        cleaned.append(t)
    return cleaned, wrote_temp
