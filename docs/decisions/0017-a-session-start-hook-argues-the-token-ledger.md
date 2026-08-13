# 0017. A SessionStart hook argues the token ledger for owasp-secure-coding

Date: 2026-08-13

## Status

Accepted. Extends ADR [0012](0012-enforcement-mechanisms.md), and departs from its
scoping rule deliberately — see *Consequences*.

## Context

`owasp-secure-coding` is found and declined, not missed. `docs/discoverability.md`
records the session that saw it, priced it, and declined it as "process overhead
without new insight here", then produced an SSRF repair plan proposing an allowlist
over domains, paths and ports that never mentioned protocols — the first dimension
ASVS V1.3.6 enumerates.

That distinction is the whole context, because it disposes of the obvious fix. A
longer or better-worded description would have changed nothing: the description was
not what was consulted at the moment of the decision, and it is already enforced past
120 characters by `test_skill_frontmatter_has_name_and_description`. Findability was
never the problem. Being chosen was.

`flag_security_topic` backstops the same failure, but only where a prompt names one of
fourteen unambiguous vulnerability classes or carries a CVE id. `security_terms.py`
deliberately excludes `token`, `session`, `cookie`, `auth`, `crypto`, `logging` and
`error handling`, because a hook matching those matches most prompts and becomes
wallpaper. That exclusion is correct and it leaves a hole: most security-relevant work
arrives in exactly the excluded vocabulary, and nothing fires there.

A `SessionStart` hook is the one mechanism that fires without a vocabulary match and
without being chosen. That is its entire justification, and also its entire problem.

## Decision

**The payload argues the ledger, and reports nothing.** It is admitted under
c7-marketplace ADR 0010's second kind — reference content — on economics: injection is
priced in input tokens, while the failure it prevents is priced in output tokens twice
over, the fix that was wrong and then the fix that is right, plus the review that
missed it and the reopened issue in between.

The first proposal was ADR 0010's *first* kind: a scan of the working directory
reporting the security surface it found. That was rejected in favour of arguing
economics. The consequence is worth stating plainly, because it is a property a reader
can rely on: no scan runs, the hook never touches the target repository, and it reads
nothing but the stdin it discards. A hook that reported findings would have to be
right about them; one that argues a cost does not.

The argument is deliberately odds-independent. It claims only that the correction
costs more than the read — not that the check is likely to find anything. This is not
rhetorical economy. The recorded failure was a cost/benefit judgement made *before
looking*, so an argument that first requires the agent to believe the check is
valuable is disposed of by exactly the reasoning that produced the failure.

**Both notices are asked for.** The activation notice follows c7-marketplace ADR 0012:
a skill that triggered and was ignored leaves the same transcript as one that never
triggered. The decline notice extends that to the half the ADR does not cover, and it
can live only in the hook. `SKILL.md` is unreachable to an agent that decided against
the skill, so an instruction placed there covers activations only — which is why no
decline line was added to the skill body, where it would cover strictly less and imply
the hook's copy was redundant.

What the decline notice buys is an interrupt. A reason stated at the time is one the
reader can overrule while the work is still open; the same reason recovered afterwards
is only an explanation. In the recorded case the reasoning was checkably wrong and
nobody was positioned to say so, because nobody knew a decision had been made.

Both notices share a weakness, stated rather than hidden: neither is enforcement.
Nothing downstream consumes either line, an agent can skip both silently, and that is
precisely the shape ADR [0003](0003-baked-index-not-runtime-fetch.md) records as
skipped 100% of the time. They are asked for because the alternative is no trace at
all, not because asking works.

**The probe-phrasing measurement was excluded.** It is step 2 of a procedure, and ADR
0003 holds that a summary complete enough to act on is a reason not to read the skill.
c7-marketplace ADR 0010 excuses `c7-coding-standards` on the grounds that a standard is
not a procedure; a retrieval protocol is one, so the excuse does not transfer.

## Consequences

- **The payload is 2,205 characters, roughly 550 tokens, and it is paid at every
  `startup`, `clear` and `compact` — not once per session.** A long session that
  compacts twice pays it three times. It reached that size after two trims from a
  first draft of 2,618 characters (~650), against a design estimate of 430 that was
  simply wrong. The first trim removed a worked SSRF example and saved 37 tokens
  rather than the 180 predicted, because the replacement restated the same claims at
  the same length; the second compressed the decline notice's rationale and did the
  real work. The small finding worth keeping is the method, not the number: a
  payload's cost is a thing to measure, not to eyeball, and the estimate was out by
  50% in the direction that matters.

- **This is the first hook the plugin ships with no scoping at all.** ADR 0012 holds
  that scoping is what makes a hook shippable; the other three are keyed to the
  session that armed them or to a vocabulary match plus a once-per-session marker.
  This one has no arming and no condition, and its only bound is that it is short.
  That is recorded here as a known weakness rather than a solved one. If it proves to
  be wallpaper, the fix is a condition, not shorter wording.

- **A session naming a vulnerability class pays twice**, once here and once for
  `flag_security_topic`. That was accepted rather than fixed. The two payloads argue
  in different currencies — tokens here, the six measured minutes there — and neither
  is a trim of the other, so collapsing them would cost one of the two arguments to
  save a few hundred tokens in the minority of sessions that trigger both.

- **It invents a drift failure that did not exist before.** The payload names the
  classes the *other* hook fires on, so a term added to `security_terms.py` leaves the
  payload silently wrong about the mechanism it describes.
  `test_the_payload_names_every_class_the_other_hook_fires_on` compares the two
  surfaces and is the only thing standing between that edit and a payload that
  understates what is already covered.

- **The trims cost the payload its only measured evidence.** The SSRF case — an
  allowlist correct in shape and short the protocol dimension — was the one concrete
  thing in it, and the argument is weaker in the abstract. It survives in
  `flag_security_topic`'s payload, in `owasp-secure-coding`'s body and in
  `docs/discoverability.md`, so it is not lost from the project; it no longer reaches
  a session that triggers none of those, which is exactly the session this hook exists
  for.
