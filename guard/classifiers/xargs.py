"""xargs: read-only only when the command it runs is a pure read.

``xargs`` builds and RUNS a command, appending items read from stdin as extra
operands. Those injected operands are invisible to us, so the wrapped command
must be read-only *independent of its operands*. We therefore allow ``xargs``
only when the wrapped command classifies to ``ALLOW`` with an EMPTY reason — a
pure / operand-independent read (see ``classifiers/base.py``). A non-empty reason
means the allow was operand-dependent (e.g. ``tmpwrite``'s "confined temp write",
whose safety rests on operands xargs would replace) -> defer. ``rm``/``tee``/etc.
deny outright. This blocks ``find / | xargs rm`` while allowing the ubiquitous
``find … | xargs grep``.

Unlike ``env``/``command`` (which merely detect that a command would run and
defer), this is the first classifier to *recursively* dispatch through the
registry. ``registry`` imports every classifier module at load time, so we import
``CLASSIFIERS`` lazily inside ``classify`` to avoid an import cycle.

FAIL SAFE: any xargs option we don't recognize -> defer, so we never misread its
argument as the wrapped command.
"""

from .base import ALLOW, deny

NAMES = ("xargs",)

# xargs long options that take NO argument (``--replace``/``--eof`` have an
# OPTIONAL value that, per GNU, may only attach via ``=`` — so bare they consume
# nothing and the next token is the command).
_LONG_NOARG = {
    "--null", "--no-run-if-empty", "--verbose", "--exit", "--interactive",
    "--open-tty", "--version", "--help", "--replace", "--eof",
}
# xargs long options that take a SEPARATE argument (the following token).
_LONG_VALUE = {
    "--arg-file", "--max-lines", "--max-args", "--max-procs", "--max-chars",
    "--delimiter", "--process-slot-var",
}
# Short-option letters that take an argument (attached, ``-n5``/``-I{}``, or the
# next token, ``-n 5``/``-I {}``).
_SHORT_VALUE = set("aEILnPsd")
# Short-option letters that take no argument (bundleable, e.g. ``-0r``).
_SHORT_NOARG = set("0rtxpo")


def classify(tokens):
    args = tokens[1:]
    i = 0
    while i < len(args):
        t = args[i]
        if not t.startswith("-") or t == "-":
            break  # first non-option token starts the wrapped command
        if t == "--":
            i += 1
            break  # explicit end of options
        if t.startswith("--"):
            if "=" in t or t in _LONG_NOARG:
                i += 1
                continue
            if t in _LONG_VALUE:
                i += 2  # skip the option and its argument
                continue
            return deny(f"xargs option we don't auto-trust: {t}")
        # Short option (or bundle). Inspect the first letter.
        c = t[1]
        if c in _SHORT_VALUE:
            i += 1 if len(t) > 2 else 2  # attached value vs. next token
            continue
        if set(t[1:]) <= _SHORT_NOARG:
            i += 1
            continue
        return deny(f"xargs option we don't auto-trust: {t}")

    wrapped = args[i:]
    if not wrapped:
        return ALLOW  # bare xargs defaults to `echo` — a pure read

    from ..registry import CLASSIFIERS

    fn = CLASSIFIERS.get(wrapped[0])
    if fn is None:
        return deny(f"xargs runs unknown command: {wrapped[0]}")
    ok, reason = fn(wrapped)
    # Only an operand-independent pure read (empty reason) is safe: xargs injects
    # unseen stdin operands, so an operand-dependent allow can't be trusted.
    if ok and not reason:
        return ALLOW
    return deny(reason or "xargs target is not provably read-only")
