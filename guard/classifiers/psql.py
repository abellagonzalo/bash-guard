"""psql: allow provably read-only connection + a single safe query/meta-command.

Unlike a flag allowlist, psql's danger lives in the *content* of one argument:
``-c "select 1; drop table x"`` is a single CLI token, so denying "the wrong
flag" doesn't help -- the ``-c``/``--command`` VALUE itself must be proven to
be exactly one read-only statement.

``-f``/``--file`` always defers: a script file's content is opaque to us, same
reasoning as ``sed.py``'s ``-f``. Connection flags (``-h``/``-p``/``-U``/``-d``)
and bare positionals (dbname/username/a conninfo string/URI) are never
content-inspected -- psql's own grammar only accepts them as connection info,
so there's no operand shape there that carries executable content.

The ``-c`` value check is deliberately narrower than a naive
``^\\s*(SELECT\\b|\\\\[a-z]+)`` pattern would be: that shape would let
``\\copy`` through (it matches ``\\\\[a-z]+``) even though ``\\copy`` can read
or write arbitrary files. We instead require a backslash meta-command to be in
an explicit safe set (schema/catalog introspection and display toggles only)
and additionally reject ``SELECT ... INTO`` (Postgres's INTO-clause creates a
table -- a write disguised as a read) and anything not starting with
``SELECT``/a safe meta-command at all (which also rejects a
``WITH ... AS (INSERT ... RETURNING ...) SELECT ...`` CTE smuggling a write,
since it doesn't start with ``SELECT``).

Fail safe, like ``sed.py``: the ``;``-splitting used to detect "more than one
statement" is a naive substring check, not a real SQL tokenizer, so a value
containing a semicolon inside a string literal defers unnecessarily rather
than risking a false allow.
"""

import re
from typing import List, Optional

from .base import ALLOW, Result, deny
from .flags import flag_value

NAMES = ("psql",)

# Flags whose value is plain connection info -- never content-inspected.
_VALUE_FLAGS = {"h", "p", "U", "d"}
_LONG_VALUE_FLAGS = {"--host", "--port", "--username", "--dbname"}

# Meta-commands that only read schema/catalog metadata or toggle display
# options -- no file/shell access. Notably excludes \copy, \i/\ir, \o, \g,
# \w, \e/\ef/\ev, \!, \set, \c -- every meta-command that can read or write
# an arbitrary file, open an editor, or shell out.
_SAFE_META_COMMANDS = {
    "d", "dt", "di", "dn", "dv", "df", "dg", "du", "dp",
    "l", "z", "x", "timing", "conninfo", "?", "h",
}

_META_RE = re.compile(r"^\\([A-Za-z?]+)\+?(?:\s|$)")
_SELECT_RE = re.compile(r"^select\b", re.IGNORECASE)
_INTO_RE = re.compile(r"\binto\b", re.IGNORECASE)


def _is_safe_sql_value(value: Optional[str]) -> bool:
    if not value or "\n" in value or "\r" in value:
        return False

    v = value.strip()
    if not v:
        return False

    if v.endswith(";"):
        v = v[:-1].rstrip()
    if ";" in v:
        return False  # more than one statement

    if v.startswith("\\"):
        m = _META_RE.match(v)
        if not m:
            return False
        return m.group(1).lower() in _SAFE_META_COMMANDS

    if _SELECT_RE.match(v):
        return not _INTO_RE.search(v)

    return False


def classify(tokens: List[str]) -> Result:
    args = tokens[1:]
    i, n = 0, len(args)
    while i < n:
        t = args[i]

        # ----- long flags: --name or --name=value -----
        if t.startswith("--"):
            name, sep, val = t.partition("=")
            has_val = bool(sep)
            if name == "--file":
                return deny("psql -f/--file reads an un-inspectable script file")
            if name == "--command":
                value, i = flag_value(args, i, val if has_val else None)
                if value is None or not _is_safe_sql_value(value):
                    return deny(
                        "psql -c/--command value is not a proven single "
                        f"read-only statement: {value!r}"
                    )
                continue
            if name in _LONG_VALUE_FLAGS:
                _, i = flag_value(args, i, val if has_val else None)
                continue
            if name == "--expanded":
                i += 1
                continue
            return deny(f"psql flag outside the connection-info allowlist: {t}")

        # ----- short flags: -x, -xVALUE, or a separate value -----
        if t.startswith("-") and t != "-":
            if t.startswith("-f"):
                return deny("psql -f/--file reads an un-inspectable script file")
            if t.startswith("-c"):
                attached = t[2:] if len(t) > 2 else None
                value, i = flag_value(args, i, attached)
                if value is None or not _is_safe_sql_value(value):
                    return deny(
                        "psql -c/--command value is not a proven single "
                        f"read-only statement: {value!r}"
                    )
                continue
            if t == "-x":
                i += 1
                continue
            if len(t) >= 2 and t[1] in _VALUE_FLAGS:
                attached = t[2:] if len(t) > 2 else None
                _, i = flag_value(args, i, attached)
                continue
            # Any other flag, incl. an ambiguous bundle like -xc: fail closed.
            return deny(f"psql flag outside the connection-info allowlist: {t}")

        # Bare operand: dbname, username, a postgresql://... URI, or a
        # key=value conninfo string -- plain connection info, not inspected.
        i += 1

    return ALLOW
