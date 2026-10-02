#!/usr/bin/env python3
"""Argue the token ledger for owasp-secure-coding, at every session start.

WHY THIS EXISTS. The skill is found and declined, not missed. Its description is
already 120+ characters of trigger vocabulary, and `docs/discoverability.md` records
the session that saw it, priced it, and declined it as "process overhead without new
insight here". A longer description would not have changed that: the description is
not what was consulted at the moment of the decision.

`flag_security_topic.py` backstops the same failure, but only where a prompt names one
of fourteen unambiguous vulnerability classes or a CVE id. `security_terms.py`
deliberately excludes `token`, `session`, `cookie`, `auth`, `crypto`, `logging` and
`error handling`, because a hook matching those matches most prompts and becomes
wallpaper.
That exclusion is right and it leaves a hole: most security-relevant work arrives in
exactly the excluded vocabulary, and nothing fires there. A SessionStart hook is the
one mechanism that fires without a vocabulary match and without being chosen.

THE PAYLOAD ARGUES ECONOMICS, NOT VALUES. c7-marketplace ADR 0010 admits reference
content on the grounds that injection is priced in input tokens while the failure it
prevents -- work done wrong, then redone -- is priced in output tokens twice over.
That argument is what the payload says, applied to retrieval instead of to a threshold
table. It is deliberately odds-independent, because the recorded failure was a
cost/benefit judgement made before looking: an argument requiring the agent to first
believe the check is valuable is disposed of by exactly the reasoning that produced
the failure.

WHY THE DECLINE NOTICE LIVES HERE AND NOWHERE ELSE. `SKILL.md` carries the
announcement for the case where the skill is used. It cannot carry the case where it
is not, because an agent that decides against the skill never reads its body. Only
something firing unconditionally can ask for that line. It is also what gives the
reader an interrupt: a stated reason can be overruled while the work is still open,
where the same reason recovered afterwards is only an explanation.

UNCONDITIONAL, WHICH IS A KNOWN WEAKNESS. ADR 0012 holds that scoping is what makes a
hook shippable, and the other three are scoped -- two by the session that armed them,
one by vocabulary plus a once-per-session marker. This one has no arming and no
condition; its only bound is that it is short. Recorded in ADR 0017 rather than
mitigated. If it proves to be wallpaper the fix is a condition, not shorter wording.

FAILS OPEN, deliberately. Any exception exits 0 and emits nothing. It runs at session
start, so failing closed would break session startup over a reminder, and the degraded
state is exactly the behaviour the plugin had before this hook existed -- recognisable
and survivable. Per ADR 0012 that direction is argued here rather than copied from the
other three.

Python rather than node, for the reason block_excluded_reads.py gives: node is not
present in this project's container, and a hook its own CI cannot exercise is an
unexercised path by construction.
"""

from __future__ import annotations

import json
import os
import sys

NUDGE = """`owasp-kb` is installed: the OWASP corpus (ASVS 5.0.0, Cheat Sheet Series) \
and MITRE's CWE catalogue, served locally over MCP, with the `owasp-secure-coding` \
skill in front of it.

**Reaching for it is a ledger argument, not a values one.** Retrieval is input \
tokens: a search and a section or two, read once, before an approach is chosen. \
Rework is output tokens, and it is paid twice -- the fix that was wrong, then the fix \
that is right -- plus the review that missed it, the branch, and the reopened issue in \
between. Input is the cheap side, and it is the side spent before the mistake exists. \
That holds without any estimate of how likely the check is to find something. It needs \
only that the correction cost more than the read, which it does.

**What causes the rework is a fix correct in shape and short a dimension** -- one \
that is invisible from inside the reasoning that produced it. What the corpus gives \
that recall cannot is the enumeration of dimensions a fix has to cover, plus a \
citable id a reviewer can check. What it cannot give is whether this codebase \
already has the control -- that comes from the codebase, and a citation does not \
stand in for it.

**Say which way you went, either way.** When you use the skill: **Using \
owasp-secure-coding to <purpose>.** When you consider it and decide against, one line \
with the reason: **Not using owasp-secure-coding: <why>.**

The second matters more: the failure recorded here was declined as "process overhead \
without new insight here", and that surfaced only when someone asked afterwards -- too \
late to act on. Stated at the time, it is a line the reader can overrule."""


def _context() -> str:
    """The text to inject.

    stdin is read and discarded: emission is unconditional, so nothing in the
    payload is consulted. It is read anyway rather than left in the pipe, and it is
    read inside this function so that main()'s handler covers it.
    """
    sys.stdin.read()
    return NUDGE


def main() -> int:
    try:
        # Serialised in full before anything is written: json.dump streams chunks
        # into the stream, so a mid-write failure leaves a truncated object on
        # stdout, which is worse than the nothing this hook promises.
        payload = json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": _context(),
                }
            }
        )
        # Written through a duplicate of fd 1, never through sys.stdout. A failed
        # write leaves the payload sitting in sys.stdout's buffer, and CPython
        # flushes that again at interpreter shutdown -- outside any handler, which
        # sets exit status 120 whatever main() returned. Nothing is ever buffered on
        # sys.stdout, so that retry has nothing left to fail on. Measured: the
        # sys.stdout form exits 120 on CI and on Python 3.14; this form exits 0.
        with os.fdopen(os.dup(1), "wb") as out:
            out.write(payload.encode())
    except Exception:  # noqa: BLE001 -- see FAILS OPEN above
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
