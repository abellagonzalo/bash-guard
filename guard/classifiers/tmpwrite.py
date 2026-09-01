"""Write commands confined to a temp directory.

These commands mutate the filesystem, so they are auto-allowed ONLY when every
write they perform lands under an allowed temp root (see ``guard/paths.py``).

Two rule shapes:

* ``touch``, ``mkdir``, ``tee``, ``rm`` -> EVERY operand must be a temp path.
  This is provably safe against a false "allow": any non-temp token — a real
  target OR a flag's argument (``-r ref``, ``-t stamp``, ``-m mode``) — forces a
  defer. These commands have no flag that redirects a write elsewhere.
* ``mv``, ``cp`` -> use a strict arg-less flag whitelist so a flag can't silently
  redirect the destination (notably ``-t`` / ``--target-directory``, which
  ``_classify_all_tmp`` would skip over and never check). ``mv`` also *removes*
  the source, so EVERY operand must be temp; ``cp`` only reads its sources, so
  only the destination (last operand) must be temp.
"""

from .base import deny
from ..paths import is_tmp_path

NAMES = ("touch", "mkdir", "tee", "rm", "mv", "cp")

# Success result: read-only-safe to auto-allow (True), but with a reason that
# flags the confined temp write so the orchestrator can label the decision
# honestly (see guard/cli.py and classifiers/base.py).
_TEMP_WRITE = (True, "confined temp write")

# cp short flags that take NO argument. Anything else (a long ``--`` option or an
# unknown short flag such as ``-t``/``--target-directory``) makes cp defer, since
# it could move the destination out from under the "last operand" heuristic.
_CP_NOARG_FLAGS = set("rRpafnviLHP")

# mv short flags that take NO argument. ``-t``/``--target-directory`` and any
# other value-taking / long flag are excluded so they can't redirect the write
# out of the temp dir (``T`` is ``--no-target-directory``, which is safe).
_MV_NOARG_FLAGS = set("finuvT")


def classify(tokens):
    cmd = tokens[0]
    args = tokens[1:]
    if cmd == "cp":
        return _classify_cp(args)
    if cmd == "mv":
        return _classify_mv(args)
    return _classify_all_tmp(args)


def _split(args, noarg_flags=None):
    """Split args into operands, honoring ``--`` as end-of-options.

    If ``noarg_flags`` is None, every ``-``-prefixed token (other than a bare
    ``-``) is silently skipped -- used by ``_classify_all_tmp``, whose target
    commands have no flag that redirects a write elsewhere.

    If ``noarg_flags`` is given, a flag is only skipped when all its letters
    are in ``noarg_flags``; otherwise splitting stops immediately and the
    offending token is returned as the second element, so the caller can
    ``deny()`` with its own command-specific message.

    Returns ``(operands, bad_flag_or_None)``.
    """
    operands = []
    end_of_opts = False
    for t in args:
        if not end_of_opts and t == "--":
            end_of_opts = True
            continue
        if not end_of_opts and t.startswith("-") and t != "-":
            if noarg_flags is not None and (
                t.startswith("--") or not set(t[1:]).issubset(noarg_flags)
            ):
                return operands, t
            continue
        operands.append(t)
    return operands, None


def _classify_all_tmp(args):
    """Every non-flag operand must be a temp path; require at least one."""
    operands, _ = _split(args)
    if not operands:
        return deny("no operand")
    for op in operands:
        if not is_tmp_path(op):
            return deny(f"write target not under a temp dir: {op}")
    return _TEMP_WRITE


def _classify_cp(args):
    """Sources unrestricted (read-only); destination (last operand) must be a
    temp path. Defer on any flag that isn't an arg-less whitelisted short flag."""
    operands, bad = _split(args, _CP_NOARG_FLAGS)
    if bad is not None:
        # Only arg-less short flags are safe; anything else could redirect
        # the destination (e.g. -t / --target-directory).
        return deny(f"unsupported cp flag: {bad}")
    if len(operands) < 2:
        return deny("cp needs a source and a destination")
    dest = operands[-1]
    if not is_tmp_path(dest):
        return deny(f"cp destination not under a temp dir: {dest}")
    return _TEMP_WRITE


def _classify_mv(args):
    """mv removes its source, so EVERY operand must be a temp path. Only arg-less
    whitelisted short flags are allowed; anything else (esp. ``-t`` /
    ``--target-directory``, in ``-tDIR`` / ``--target-directory=DIR`` / separated
    forms) could redirect the destination out of temp -> defer."""
    operands, bad = _split(args, _MV_NOARG_FLAGS)
    if bad is not None:
        return deny(f"unsupported mv flag: {bad}")
    if not operands:
        return deny("no operand")
    for op in operands:
        if not is_tmp_path(op):
            return deny(f"write target not under a temp dir: {op}")
    return _TEMP_WRITE
