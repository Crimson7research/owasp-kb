---
name: tracing-to-a-consumer
description: Trace every new output, instruction, parameter or agent role to the thing that actually requires it, before believing it works. Use this when reviewing a change, adding a field to a response, writing an instruction into a skill or agent prompt, wiring one agent to another, or whenever tests pass but you have not seen the feature work end to end. This is the dominant bug class in this repo — six issues and counting — and it is invisible in a diff, so reach for it during design and review rather than after a failed run.
---

# Tracing to a consumer

The recurring bug here has one shape: **something is produced, nothing downstream requires it,
so it silently does not happen — and every test still passes.** Six issues, all the same:

| Issue | Produced | Nothing required it | Result |
|---|---|---|---|
| #8 | Cheat Sheet corpus, 120 docs | no output column consumed guidance | 62-finding report, corpus untouched |
| #15 | `owasp-finding-verifier` role | no consumer of its trace | 0 dispatches across 172 findings |
| #19 | "ToolSearch for the owasp-kb tools" | the allowlist forbade holding them | 3 of 5 roles silently toolless |
| #20 | a completed report | nothing distinguished it from a fragment | truncation read as an answer |
| #21 | 10 finder verdicts | orchestrator returned before collecting | 0 of 10 recovered |
| #25 | finder emits `PASS` | roster accepts `MET` | assembly would reject every pass |

None of these was a wrong line of code. Each was a correct line with nothing on the other end.

## The method

For each new artefact — a response field, an instruction, a parameter, a role — write down three
things:

1. **Producer**: what emits it, `file:line`
2. **Consumer**: what requires it, `file:line`
3. **Handoff**: where it crosses between them

If you cannot fill in the consumer, that is the bug. Not a risk, not a smell — the thing will not
run and nothing will tell you.

The mechanical version takes seconds:

```bash
grep -rn "not_applicable" .
```

If every hit is where the artefact is *produced* — plus documentation about it — nothing consumes
it. That one command found a feature that was completely inert: an orchestrator built
`not_applicable` entries carrying refuter traces, and no skill ever passed them to
`owasp_roster`, so every one was silently re-filed as `INSUFFICIENT EVIDENCE`. Every test passed,
because the strings all existed — in a file nobody read them from.

## Where it hides in a fan-out

Multi-agent flows have more seams than they look like they do. Producer and consumer are often in
different files written at different times, and both read fine alone:

```
main session ──inventory──▶ orchestrator ──requirement──▶ finder
                    │                          │
                    │                          └── verdict ──▶ ??? 
                    └── not_applicable ──▶ ???
```

Two failures here came from exactly the arrows above. `owasp-requirement-finder` had a full
"Excluded material" section that nothing could populate, because finders are dispatched by the
*orchestrator*, not the main session, and the orchestrator was not forwarding the list — a
consumer with no producer, the same bug inverted.

Worth checking specifically:

- **Vocabulary across a seam.** Both sides can be internally consistent and still disagree. The
  finder's `PASS` and the roster's `MET` were each coherent; nothing tested the boundary.
- **Instructions in prose versus the numbered process.** An agent treats a numbered `## Process`
  as its checklist. An instruction sitting in a prose section above it may never execute.
- **Anything an agent "should" do.** If no downstream step fails when it doesn't, it won't.

## How these actually got caught

Not by reading diffs — that found none of them. What worked:

- **`grep` for the artefact name** across the whole repo, producers versus consumers
- **Mutation testing**: break the code, confirm a test fails. Three surviving mutants in one unit
  and ten of eighteen in another were tests that could not fail.
- **Reading a prompt file top to bottom as the executing agent**, walking a concrete scenario and
  asking at each step whether the next move is unambiguous
- **Running the pipeline.** The `PASS`/`MET` seam survived 465 tests and five review rounds and
  died in the first minute of a real run.

## Making the consumer required

Finding the gap is half of it. The fix that holds is making the result *necessary* rather than
requested:

- `owasp_roster` rejects a `GAP` with no verifier trace — so the verifier must run
- every role ends with `REPORT COMPLETE` and its absence is treated as failure — so a truncated
  report cannot pass as an answer
- the roster rejects a finding citing an excluded path — so the exclusion is not merely asked for

The pattern: put the check at a point the whole flow must pass through, and make the missing
thing an error rather than an absence. An instruction that something *should* happen is the
weakest available mechanism, and this repo has six issues demonstrating it.

## When you are writing the plan, not the code

The same gap appears one level up. Four defects in one implementation cycle entered through plan
blocks that specified an artefact with no consumer, were faithfully transcribed, and passed spec
review because the code did match the spec. If you are writing a plan, name the consumer for each
new artefact in the plan itself — it is far cheaper than discovering it after several subagents
have built on top.
