"""python/python3: read-only only for the literal ``-c '<script>'`` shape.

Sibling of ``bash.py``'s ``-c`` recognition (issue #28, sibling of #16's closed,
deliberately-unimplemented heredoc carve-out): ``python3 -c "<script>"`` is a
single shlex token by the time it reaches ``classify()`` (``guard/parser.py``'s
``to_segments()`` already resolves the quoting), so extracting the script body
needs no new parsing. What's hard, and the reason #16/#28 both say "do not
implement without a second look", is proving the script itself is read-only.

Unlike ``bash.py`` (which recurses the script text through this same shell
classifier pipeline), Python source can't be vetted by scanning for mutating
NAMES: reflection lets it reach ``os``/``subprocess`` without ever spelling
those names literally, e.g. ``().__class__.__bases__[0].__subclasses__()``
walks to arbitrary loaded classes, or ``getattr(x, "__cla" + "ss__")`` builds a
dunder name at runtime. A denylist of names is not sound against that. Instead
``_is_safe_script()`` parses with ``ast`` and applies three independent,
structural restrictions, each closing a different escape class:

1. **Import allowlist, not denylist** (``_SAFE_IMPORTS``) — only pure
   data-format/computation modules with no filesystem/process/network surface
   may be imported. This is the primary boundary: if ``os``/``subprocess``/
   ``socket``/... can never be imported, the concrete damage they'd do is
   unreachable through the ordinary (non-reflection) path.
2. **Blanket dunder-attribute ban** — any ``obj.__anything__`` access anywhere
   in the script, regardless of receiver. This is what closes the reflection
   escape class above: it doesn't matter whether ``os`` was ever imported if
   ``().__class__.__bases__`` can walk to it anyway.
3. **Dangerous builtin calls** (``_UNSAFE_CALLS``) — ``eval``/``exec``/
   ``compile``/``getattr``/``setattr``/... ``getattr``/``setattr`` matter even
   with #2, since ``getattr(x, "__cla" + "ss__")`` builds the same attribute
   name as a runtime string rather than a literal ``.__class__`` access.

Plus two narrower checks: ``open()`` calls are allowed only with no mode
argument or a literal safe read mode (``_is_safe_open_call``), and a short
defense-in-depth blocklist of dangerous attribute/method names
(``_UNSAFE_ATTRS``) catches a dangerous method surfacing on an allowed module
in the future, independent of whether #1/#2 already block it today.

This is deliberately NOT the same soundness guarantee as this codebase's other
classifiers: ``git``/``docker``/``kubectl``'s ``find_subcommand()`` fail-safe
reasons about a closed, fixed CLI grammar; this reasons about an open-ended,
Turing-complete language. The above closes every publicly known "AST-level
sandbox escape without a disallowed import or a literal dunder" technique, not
every technique that could ever exist. Widen ``_SAFE_IMPORTS`` only by
addition; never loosen the dunder-attribute ban or ``_UNSAFE_CALLS``.
"""

import ast
from typing import List, Optional

from .base import ALLOW, Result, deny

NAMES = ("python", "python3")

# Pure data-format / computation modules only -- no filesystem, process, or
# network surface. Anything else (os, sys, subprocess, shutil, socket,
# pathlib, importlib, pickle, ctypes, ftplib, http, urllib, ...) is denied.
_SAFE_IMPORTS = frozenset(
    {
        "json", "csv", "re", "math", "itertools", "collections", "datetime",
        "textwrap", "string", "pprint", "statistics", "decimal", "fractions",
        "functools", "operator", "typing", "dataclasses", "enum", "base64",
        "hashlib", "difflib", "unicodedata",
    }
)

# Builtins that can execute arbitrary code, reflectively resolve a name, or
# block on stdin -- denied regardless of the dunder-attribute ban above.
_UNSAFE_CALLS = frozenset(
    {
        "eval", "exec", "compile", "getattr", "setattr", "delattr",
        "globals", "locals", "vars", "__import__", "input",
    }
)

# open()'s mode argument (positional or keyword) is safe only if absent or a
# literal string in this set.
_SAFE_OPEN_MODES = frozenset({"r", "rt", "rb"})

# Defense-in-depth: mutating/process/network method names, regardless of
# receiver, denied even though _SAFE_IMPORTS + the dunder ban should already
# make their real modules unreachable.
_UNSAFE_ATTRS = frozenset(
    {
        "write", "writelines", "remove", "unlink", "rmtree", "system",
        "popen", "Popen", "connect", "send", "socket", "truncate", "chmod",
        "chown", "rename", "replace", "kill",
    }
)


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _is_safe_open_call(node: ast.Call) -> bool:
    mode_node: Optional[ast.expr] = None
    if len(node.args) >= 2:
        mode_node = node.args[1]
    else:
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
                break
    if mode_node is None:
        return True  # defaults to "r"
    if not (isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str)):
        return False  # non-literal mode -- can't prove statically
    return mode_node.value in _SAFE_OPEN_MODES


def _is_safe_script(text: str) -> Optional[str]:
    """Return None if the script passes every check, else a deny reason."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        return f"script does not parse: {exc}"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in _SAFE_IMPORTS:
                    return f"import outside the safe module set: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top not in _SAFE_IMPORTS:
                return f"import outside the safe module set: {node.module}"
        elif isinstance(node, ast.Attribute):
            if _is_dunder(node.attr):
                return f"dunder attribute access: {node.attr}"
            if node.attr in _UNSAFE_ATTRS:
                return f"unsafe attribute/method name: {node.attr}"
        elif isinstance(node, ast.Name):
            if _is_dunder(node.id):
                return f"dunder name reference: {node.id}"
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in _UNSAFE_CALLS:
                    return f"unsafe call: {func.id}"
                if func.id == "open" and not _is_safe_open_call(node):
                    return "open() with a non-read mode"

    return None


def classify(tokens: List[str]) -> Result:
    args = tokens[1:]
    if not (len(args) >= 2 and args[0] == "-c"):
        return deny(
            "python/python3 without a literal -c '<script>' as its first "
            "argument is not analyzed"
        )

    script = args[1]
    reason = _is_safe_script(script)
    if reason is not None:
        return deny(f"python -c script is not read-only: {reason}")
    return ALLOW
