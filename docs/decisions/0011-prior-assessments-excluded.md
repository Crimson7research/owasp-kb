# 11. Prior assessments are excluded from evidence; design documentation is not

## Status

Accepted. One violation has already been observed in the field and is recorded
below rather than treated as hypothetical.

## Context

Assessments get run against targets that have been assessed before. A prior
report sitting in `docs/security/` is the single most attractive document in the
repository to an agent trying to answer 253 requirements: it is organised by the
same requirement ids, it states verdicts, and it reads as authoritative.

Using it is not verification. Another assessment's conclusion is not evidence,
and an agent that reads one tends to confirm it rather than test it — which
turns a second assessment into a restatement of the first, including the first's
mistakes, while looking like independent corroboration.

The obvious control — exclude `docs/` — is wrong, and is wrong for a reason
specific to ASVS. A documentation-class requirement asks whether something is
*written down*: `V7.1.1` is literally "verify that the session timeout is
documented". Answering it requires reading `docs/`. Excluding the directory
would make an entire class of requirements unanswerable, which would convert
them into `INSUFFICIENT EVIDENCE` verdicts at scale — the failure mode this
project is trying to eliminate, arrived at from the opposite direction.

So the line is not a directory. It is a *kind* of document.

## Decision

**Other people's findings are out. Design documentation is in.**

Prior security assessments, audits, pentest reports and security reviews of the
same target are excluded from evidence. Design documentation, architecture
notes and threat models are primary evidence and are read normally.

The mechanism has three parts:

1. **Discovery, during the scope interview.** The main session looks for prior
   assessments before dispatching anything — `docs/security/`, files named for
   ASVS, audit, pentest or security review — lists the paths to the user, and
   confirms they are to be excluded rather than used.

2. **Agents are told the files exist**, not kept ignorant of them. The list is
   forwarded to every dispatched agent (the chapter orchestrator is the only
   thing that dispatches finders and refuters, so it forwards it explicitly).
   Telling them means no agent wastes turns rediscovering a report and
   deliberating over it, and the final report can state that a prior assessment
   was present and deliberately not consulted — which is itself a fact the
   reader needs.

3. **Enforcement is a citation check at the assembly point.** The same list goes
   to `owasp_roster` as `excluded`, which rejects any finding citing an excluded
   path in its `file`, `evidence`, `trace` or `remediation`. A contaminated
   verdict fails at assembly rather than reaching the report. This mirrors
   `require_verification` exactly and rests on the same argument as ADR
   [0010](0010-enforce-invariants-in-code.md): a rule enforced in code where the
   whole assessment must pass through, rather than asserted in a prompt that
   nothing checks.

4. **A `PreToolUse` hook refuses the read itself.** Added after this ADR was
   written, and after part 3 proved insufficient in the field. The citation check
   catches a contaminated verdict at assembly; it cannot catch an agent that read
   the report and then cited only source. `block_excluded_reads.py` denies a
   `Read`, `Grep` or `Glob` that would reach a listed path, which is the only
   point at which the text can still be stopped — filtering the output cannot
   work, because by the time hits are stripped the agent has seen them.

   The hook reads the same list, written to `sessions/<id>/excluded` (ADR
   [0013](0013-session-state-on-disk.md)). It fails open, so an unarmed hook is
   indistinguishable from one with nothing to block, and part 3 remains the real
   gate. ADR [0012](0012-enforcement-mechanisms.md) covers why a hook rather than
   an assembly-point check, and why this one fails open while other state fails
   closed.

   The three parts are different controls and all three are needed: the hook
   stops the read, the prompt tells an agent why, and the roster rejects a
   finding that cites one.

**Rejected: declared read sets** — requiring each agent to report what it read,
and checking that list. Rejected on cost, and more importantly because a
self-reported read set from an agent that ignored the rule is worth very little:
the check would be strongest exactly where it is least needed.

One refinement was forced by a contradiction the first design created.
`INSUFFICIENT EVIDENCE` and `N/A (unverified)` are exempt from the citation scan
(`NON_ASSERTING_VERDICTS`). The prompts tell an agent to say when a verdict would
depend on excluded material — and saying so naturally names the file, tripping
the check that the instruction was written around. Neither verdict concludes
anything, so neither can import a false conclusion from a prior report; a `GAP`
or a verified `N/A` still asserts something a prior report could have supplied,
so those stay in scope.

## Consequences

- **A documentation-class requirement is answerable, and answerable honestly.**
  `V7.1.1` can be verified by reading the design docs, and the fact that the
  answer came from documentation rather than code is exactly what that
  requirement asks for.
- **Enforcement stops contamination that reaches the report, and nothing else.**
  It does not catch anchoring. An agent that reads a prior report and then goes
  looking for confirming code produces a finding citing only source files and
  passes the check. Acknowledgement is not checked either: an agent that opens
  an excluded file and reports a finding without naming the path is
  indistinguishable from one that never opened it.
- **The prompt wording is already known to be ambiguous, and was violated on the
  first run under these rules.** A finder grepped the excluded prior assessment
  and quoted the hits. The prompts said *"Do not open them, grep them, or cite
  them"*, and the agent appears to have read that as permitting a grep whose
  output it then used — `grep` is not `open`. It recurred on the next run, where
  two broad `docs/**` greps recursed into the file before the query was narrowed.

  What kept it out of the report the first time was that the orchestrator
  noticed. That was encouraging and it was **not a control** — it is the same
  disposition-based catching that made the original contamination problem
  invisible in the first place, which is why part 4 exists. The wording is now
  broader in all five agents — *any tool call whose output could include text
  from these files is forbidden, and a grep is not exempt because the hit was
  not opened* — and the hook enforces it. Once armed, it fired in 36 of 145
  subagents on the next run.
- **The exclusion is only as good as the discovery step.** A prior assessment
  that the scope interview does not find is not excluded, and nothing downstream
  will notice. The interview asks the user directly for this reason.
- **Accepted risks have to come from the user, not the document.** If the only
  record of accepted risk lives inside an excluded prior assessment, the skill
  asks the user which findings are already accepted rather than reading it — a
  verdict of `FAIL (accepted)` rests on the user's statement, not on the report.
- **`excluded` is validated as a list of paths.** Passing a bare string would
  match character by character and reject essentially every finding, so
  `build_roster` raises on a string and on non-path entries, and strips blanks —
  a blank entry matches every finding, which is never what anyone means.
