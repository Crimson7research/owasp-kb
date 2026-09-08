"""The vulnerability names that route a prompt to the knowledge base.

Only names that cannot mean anything else. ``token``, ``session``, ``cookie``,
``auth``, ``crypto``, ``logging`` and ``error handling`` are deliberately absent:
they appear constantly in ordinary development conversation, and a hook that fires
on most prompts becomes wallpaper. Precision over recall -- the skill descriptions
are what cover security work phrased vaguely.

This lives beside the CLI rather than inside the hook script so tests can import
it. The hook cannot import ``owasp_kb`` itself, because that package ships inside
the container and never onto the host.
"""

from __future__ import annotations

import re

VULNERABILITY_NAMES: tuple[str, ...] = (
    "SSRF",
    "XSS",
    "CSRF",
    "XXE",
    "IDOR",
    "SQL injection",
    "command injection",
    "LDAP injection",
    "path traversal",
    "directory traversal",
    "deserialization",
    "open redirect",
    "server-side template injection",
    "privilege escalation",
)

# Word-bounded, or `XSS` matches inside an unrelated identifier and the hook fires
# on prompts with nothing to do with security. Escaped, or a name containing a
# regex metacharacter silently stops matching -- the failure would be a term that
# looks advertised and never fires.
_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(name) for name in VULNERABILITY_NAMES) + r")\b",
    re.IGNORECASE,
)

# A CVE id names a specific vulnerability without naming its class, and carries the
# same problem: you cannot tell from the inside whether you recall it accurately.
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def matched_term(prompt: str) -> str | None:
    """The first vulnerability name in ``prompt``, or None."""
    found = _PATTERN.search(prompt or "")
    if found:
        return found.group(1)
    found = _CVE.search(prompt or "")
    return found.group(0) if found else None
