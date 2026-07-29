# 10. Assessment invariants are enforced in code, at the assembly point

## Status

Accepted.

## Context

An assessment is produced by agents that cannot be trusted to follow
instructions — not through malice, but because this project has measured the
failure repeatedly. Six defects in its own history are the same shape: a prompt
said to do something, nothing downstream required the result, and it did not
happen.

| # | The instruction | What shipped |
|---|---|---|
| 8 | fetch cheat-sheet guidance for each finding | 62 findings, **0 remediation citations** — the output table had a CWE column and no guidance column, so CWE got fetched and guidance did not |
| 15 | dispatch a verifier per finding | **172 findings, 0 verifiers dispatched** |
| 19 | load the knowledge-base tools before assessing | three of five roles could not — the allowlist omitted them |
| 20 | write a complete report | agents returned their opening sentence and it read as an answer |
| 21 | collect the finders' verdicts | an orchestrator returned *"waiting for the remaining 6 background finder agents"* as its result; **0 of 10 verdicts recovered** |
| 25 | return `PASS` / `GAP` / `INSUFFICIENT EVIDENCE` | the finder emits `PASS`; `owasp_roster` accepts `MET`; nothing translates |

Two of those (#15, #19) turned out to have the tool allowlists as their
proximate cause rather than an unconsumed instruction — the "no downstream
consumer" frame was applied to #15 and then explicitly retracted by its author,
who had carried it over from #8 without checking that it fit. That correction is
worth keeping, because the record in several places still carries the
superseded framing. It does not change the conclusion: whether an instruction is
skipped because nothing consumes it or because the agent cannot obey it, the
report comes out looking complete either way.

The alternative on the table each time was to write the rule more emphatically
in the prompt. That has been tried, and the emphasis is not what was missing.

## Decision

Every invariant that can be checked from the assembled data is enforced in
`owasp_roster` (`core/roster.py`), the tool that turns per-requirement verdicts
into a report. It is the single point every assessment must pass through, and it
raises `RosterError` rather than warning:

- **An untraced claim is rejected.** `CLAIMS_NEEDING_AN_ADVERSARY` maps `GAP` to
  `owasp-finding-verifier` and `N/A (verified)` to `owasp-exemption-refuter`. A
  verdict asserting that someone checked something must carry that check.
  `GAP (unconfirmed)` and `N/A (unverified)` are the honest ways past it and
  both land in `needs_attention`; `require_verification=False` is the deliberate
  way past it, and the response reports `verification_required: false` so the
  choice is visible.
- **A finding citing an excluded prior assessment is rejected** — see ADR
  [0011](0011-prior-assessments-excluded.md).
- **A `GAP` with no file and line is rejected.** A gap with no location reaches
  the report pointing at nothing. (`N/A` and `INSUFFICIENT EVIDENCE` have no
  location by design.)
- **An incomplete roster is rejected, or completed.** A chapter with no
  applicability state fails outright. A finding citing a requirement outside the
  assessed set fails — scope and findings disagreeing is an error, not something
  to reconcile quietly. A requirement nobody reported becomes
  `INSUFFICIENT EVIDENCE` rather than vanishing: the single-agent report could
  only *assert* completeness, and here it is decided.

The decision rules that follow are deterministic for the same reason: one
refutation outweighs any number of confirmations, an errored adversary escalates
rather than counting as agreement, and findings dedupe on `(file, line, cwe, verdict)`
with unlocated findings never merging.

**An instruction with no consumer gets skipped; a required field cannot be.**

Two guards apply the same pattern where code cannot reach — inside a subagent's
own reasoning, where no assembly-point check can see:

- **The `REPORT COMPLETE` sentinel.** Every role ends its reply with it, and the
  dispatcher treats its absence as failure rather than as content. This was
  proposed as the *secondary* fix to a truncation problem and turned out to be
  the load-bearing one: on first use it caught an orchestrator that had **not**
  hit its cap (45 tool calls against 60) and had returned a status line. The
  real defect was never `maxTurns`; it was that nothing distinguished a result
  from a non-result, and truncation was merely the first cause found. A
  cap-based guard would have caught only that first cause. The sentinel catches
  the class, because it tests for *the presence of a finished answer* rather
  than for any particular way of failing to produce one.
- **`maxTurns` reframed as a rabbit-hole detector, not a budget.** Caps were
  raised to roughly 3× observed need — inventory 20→75, finder 25→75, refuter
  30→75, verifier 30→75, orchestrator 60→200 — so that reaching one means
  something went wrong rather than that the work was large. A cap a *successful*
  run can hit is measuring the wrong thing. The original values had been
  invented alongside the tool allowlists with no measurement behind them; the
  orchestrator needs 200 because it waits on up to 47 sequential finders for V6.
  Note that a turn is not a tool call: one agent made 37 tool calls inside 20
  turns, because parallel calls batch into a single turn.

## Consequences

- **The report can no longer look complete when it is not.** The counts come
  from the tool and sum to the total, so the skill reports a fact rather than
  making a claim. The three uncertain verdicts are the point of the design, and
  they are surfaced in `needs_attention` rather than being absorbed into
  confident ones.
- **This catches what reaches the report, not what an agent read.** It does not
  catch anchoring. An agent that reads a prior assessment and then goes looking
  for confirming code produces a finding citing only source, and passes every
  check here. An agent that opens an excluded file and reports a finding without
  naming the path is indistinguishable from one that never opened it. Only the
  role prompts address that, which is to say: imperfectly, by the same argument
  this ADR is built on. This limit is stated in `build_roster`'s own docstring
  so a reader of the code meets it too.
- **Honest verdicts must stay cheap, or the checks get gamed.** Because a
  missing trace is fatal, the downgrade paths (`GAP (unconfirmed)`,
  `N/A (unverified)`) have to be genuinely available — otherwise the pressure is
  to invent a trace. A near-miss proves the point: an orchestrator prompt mapped
  the refuter's default `unclear` to `N/A (verified)` with the refuter's grep
  line attached as its trace, producing an exemption that the roster accepted,
  that never appeared in `needs_attention`, and that was indistinguishable from
  a real one. It was caught in review, not by a test.
- **New seams need their own tests.** The `PASS`/`MET` mismatch (#25) sat across
  the boundary between a prompt and the code: each side was internally
  consistent, both sides' tests passed, and the first real end-to-end run hit it
  immediately. Fixed by making the finder emit `MET`, with a test asserting it
  cannot name a verdict the roster rejects. Enforcement in code moves the risk
  to the seams, and the seams are where the tests now have to go.
- **`owasp_roster` is the assessment layer's chokepoint by design**, which makes
  it the thing to keep small and total. It holds no retrieval logic and answers
  no knowledge question; it decides only whether a set of verdicts forms a
  complete, consistent, traced roster.
