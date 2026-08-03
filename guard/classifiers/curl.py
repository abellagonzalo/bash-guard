"""curl: allow provably read-only GET/HEAD requests.

curl defaults to GET. We auto-allow it only when we can prove it neither sends a
request body/upload (which implies a write verb) nor writes the response anywhere
except a temp dir. Anything else defers to the normal permission flow.

The security-relevant surface is the flag sets below; widen/narrow there. Mirrors
the ``gh api`` classifier, which allows a request only without a write method or
body.
"""

import re

from .base import ALLOW, deny
from ..paths import is_tmp_path

NAMES = ("curl",)

# Imply a request body / non-GET verb -> never a plain read.
_BODY_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "--json", "-F", "--form", "--form-string",
    "-T", "--upload-file",
}

# Write the response/metadata to a caller-named file: allowed only when that
# file lands under a temp dir (the flag's value is the target path).
_OUTFILE_FLAGS = {
    "-o", "--output", "--output-dir", "-D", "--dump-header",
    "--trace", "--trace-ascii", "-c", "--cookie-jar", "--etag-save",
    "--stderr",
}

# Write to a filename curl derives (CWD / URL / response header): can't prove it
# lands in a temp dir -> defer.
_CWD_WRITE_FLAGS = {
    "-O", "--remote-name", "--remote-name-all", "-J", "--remote-header-name",
}

# A config file could smuggle in any of the above -> can't prove GET.
_OPAQUE_FLAGS = {"-K", "--config"}

_SAFE_METHODS = {"GET", "HEAD"}

# Short-flag letters that write, send a body, or change the method. Any of these
# hidden in a bundle (e.g. ``-sO``) forces a defer.
_DANGEROUS_SHORT = set("doDcKFTXOJ")

_LEADING_LETTERS = re.compile(r"-([A-Za-z]+)")


def _method_ok(method):
    return method.upper() in _SAFE_METHODS


def classify(tokens):
    rest = tokens[1:]
    i, n = 0, len(rest)
    while i < n:
        t = rest[i]

        # ----- long flags: --name or --name=value -----
        if t.startswith("--"):
            name, sep, val = t.partition("=")
            has_val = bool(sep)
            if name in _BODY_FLAGS:
                return deny("curl with a request body/upload (implies a write)")
            if name in _OPAQUE_FLAGS:
                return deny("curl reading a config file we can't inspect")
            if name in _CWD_WRITE_FLAGS:
                return deny("curl writing to a derived filename (not provably temp)")
            if name == "--request":
                method = val if has_val else (rest[i + 1] if i + 1 < n else "")
                if not _method_ok(method):
                    return deny("curl with a non-GET HTTP method")
                i += 1 if has_val else 2
                continue
            if name in _OUTFILE_FLAGS:
                target = val if has_val else (rest[i + 1] if i + 1 < n else None)
                if not target or not is_tmp_path(target):
                    return deny(f"curl output target not under a temp dir: {target}")
                i += 1 if has_val else 2
                continue
            # Unknown long flag: value-taking ones (e.g. --header) leave their
            # value as a following operand we simply skip -> safe.
            i += 1
            continue

        # ----- short flags: -x, -x<value>, or bundles -xyz -----
        if t.startswith("-") and t != "-":
            # HTTP method: -X <m> / -X<m>  (GET & HEAD are reads).
            if t == "-X":
                method = rest[i + 1] if i + 1 < n else ""
                if not _method_ok(method):
                    return deny("curl with a non-GET HTTP method")
                i += 2
                continue
            if t.startswith("-X"):
                if not _method_ok(t[2:]):
                    return deny("curl with a non-GET HTTP method")
                i += 1
                continue

            if t in _BODY_FLAGS:
                return deny("curl with a request body/upload (implies a write)")
            if t in _OPAQUE_FLAGS:
                return deny("curl reading a config file we can't inspect")
            if t in _CWD_WRITE_FLAGS:
                return deny("curl writing to a derived filename (not provably temp)")
            if t in _OUTFILE_FLAGS:  # separated form: -o /tmp/x
                target = rest[i + 1] if i + 1 < n else None
                if not target or not is_tmp_path(target):
                    return deny(f"curl output target not under a temp dir: {target}")
                i += 2
                continue
            if t[:2] in _OUTFILE_FLAGS:  # attached form: -o/tmp/x
                target = t[2:]
                if not is_tmp_path(target):
                    return deny(f"curl output target not under a temp dir: {target}")
                i += 1
                continue

            # Any remaining single-dash token: defer if its leading letter-run
            # carries a write/body/method letter (possibly bundled), else it's a
            # safe boolean cluster or a safe value flag with an attached value.
            m = _LEADING_LETTERS.match(t)
            if m and set(m.group(1)) & _DANGEROUS_SHORT:
                return deny(f"curl short flag may write or change method: {t}")
            i += 1
            continue

        # Non-flag operand (URL, etc.).
        i += 1

    return ALLOW
