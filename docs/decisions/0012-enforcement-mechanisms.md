# 12. Three enforcement mechanisms, and which failure each can stop

## Status

Accepted. Extends ADR [0010](0010-enforce-invariants-in-code.md) rather than
replacing it.

## Context

ADR 0010 settled that assessment invariants belong in code rather than in
prompts, and put them at the assembly point: `owasp_roster`, the tool every
verdict must pass through. That was the right place for the failures it was
written about, all of which were visible in the assembled data.

Then three failures arrived that the assembly point cannot see, and each was
fixed with a different mechanism. Nothing wrote down which mechanism suits
which job, so the next person meets three unexplained precedents.

All three mechanisms below are about enforcing invariants; the
`UserPromptSubmit` routing hook and the `SessionStart` hook added later are
discovery mechanisms instead, whose case is recorded in
[docs/discoverability.md](../discoverability.md) and, for the second of them, in
ADR [0017](0017-a-session-start-hook-argues-the-token-ledger.md).

| Failure | Visible at assembly? | Fixed with |
|---|---|---|
| A finder grepped an excluded prior assessment and quoted the hit | No — the text had already reached the agent | A `PreToolUse` hook |
| Triage ran over an inventory missing one of five concerns | No — an inventory produces facts, not verdicts, so nothing counts it | A second `PreToolUse` hook |
| A report shipped with 35 of 51 gaps unverified | Yes | `owasp_roster` |

The first two are the interesting ones, because they establish where the
assembly point stops.

**An assembly-point check runs too late to stop a read.** By the time
`owasp_roster` sees a finding, the agent that produced it has already read
whatever it read. The roster rejects a finding that *cites* an excluded path,
which is a real control, but an agent that reads an excluded report and then
reports a finding citing only source code passes it — ADR 0011 records that
limit. Filtering the tool's output cannot close it either: by the time hits are
stripped, the agent has seen them.

**Some stages produce no verdict at all.** The scope inventory produces facts.
`owasp_roster` gates everything that produces a verdict, so it structurally
cannot count inventory agents. One run had four of five return, triaged all
seventeen chapters over the hole, and nothing noticed, because a triage over a
partial inventory is indistinguishable from one over a complete one.

**Skill prose gates nothing.** This is the mechanism that keeps being reached
for and keeps not working, and two instances shipped before being caught by
direct questions rather than by anything mechanical: `findings.jsonl` had a
reader and no writer, and the exclusion hook's list file fails open, so a
session that never wrote one was indistinguishable from a session with nothing
to block.

## Decision

Three mechanisms, chosen by what the failure needs stopped and when.

**`owasp_roster` — anything decidable from the assembled data.** The chokepoint
of ADR 0010, unchanged. `verification_complete` and `unassessed` were added
here, not to a prompt, because they are arithmetic over the roster: which
requirements carry a verdict nobody adversarially checked, and which nobody
looked at. A gate here cannot be skipped, because assembly is not optional.

**A `PreToolUse` hook — anything that must not happen at all.** A hook is the
only thing that can refuse a tool call before its output exists. Use it when
the damage is done by the text arriving, not by what is later reported. Two
exist: `block_excluded_reads.py` refuses a `Read`, `Grep` or `Glob` that would
reach an excluded prior assessment, and `gate_triage_on_inventory.py` refuses a
chapter-orchestrator or exemption-refuter dispatch until every concern on the
session's list has a section with a body in `inventory.md`.

A refusal states the call to make instead. A refusal an agent cannot act on
gets worked around, so returning redacted hits — or a bare denial — is worse
than useless.

**Skill prose — never for an invariant.** Prose says what to do and why. It
cannot be relied on to make anything happen, and an instruction whose result
nothing requires is indistinguishable, in the output, from one nobody wrote.
Where prose must carry a requirement, render the example rather than naming the
outcome; naming an outcome without one yields prose instead of the artefact.

### Which way each mechanism fails

This is the part that does not generalise, and the part most likely to be got
wrong by pattern-matching the last case. The table covers the fail direction of
every hook the plugin ships, including the two discovery hooks that are
otherwise outside this ADR's scope: a hook's fail direction is the wrong thing
to leave unrecorded merely because the argument for its existence lives in
another document.

| Mechanism | Fails | Because |
|---|---|---|
| `block_excluded_reads` | **open** | A hook failing closed breaks unrelated sessions on a bug of its own. The roster rejecting findings that cite an excluded path remains the real gate, so an open failure degrades to the pre-hook state rather than to nothing. |
| `gate_triage_on_inventory` | **open** | An over-refusal stops the assessment outright. There is no cheaper downstream gate, but a halt is worse than the hole it guards. |
| `findings.jsonl` loading | **closed** | A missing file read as an empty set produces a roster reporting every requirement as `INSUFFICIENT EVIDENCE` — which reads as an assessment result, not as a missing file. |
| `flag_security_topic` | **open** | It guards a reminder, so an open failure degrades to exactly the behaviour before the hook existed, which is recognisable and survivable. |
| `nudge_secure_coding` | **open** | It runs at session start, so failing closed would break session startup over a reminder. The degraded state is the behaviour the plugin had before it existed. |

The rule underneath: **fail open when the degraded state is recognisable as
degraded, and fail closed when it is indistinguishable from a legitimate
result.** An empty findings file yields a plausible-looking assessment that is
entirely wrong, and nothing downstream can tell. An unarmed exclusion hook
yields the behaviour the project had a week earlier, with another gate still
standing.

Note that all four hooks fail open and the reasoning differs for each. Four
mechanisms agreeing on a direction is not a pattern to copy — it is four
separate arguments that happened to land the same way.

### Scoping is what makes a hook shippable

A hook ships to every session of everyone who installs the plugin, including
sessions doing unrelated work. The two `PreToolUse` hooks are keyed to the
session that armed them: the exclusion list at `sessions/<id>/excluded`, the
inventory gate at that session's concerns file. A session that never ran an
assessment finds no file and every call is allowed, so for those two,
interference with unrelated work is impossible rather than unlikely. Nothing
arms the `UserPromptSubmit` routing hook — it fires in any session whose prompt
matches its vocabulary and writes its marker unconditionally — so it is scoped
the other way: by that vocabulary match and by a once-per-session marker that
holds it to a single reminder, rather than by having been armed. That bounds it
instead of excluding it, which is why its fail direction is in the table above.

The `SessionStart` hook added later is not scoped at all. Nothing arms it, no
vocabulary gates it, and it fires in every session of everyone who installs the
plugin. Its only bound is that it is short. That is a real departure from the rule
this section states, and it is a consequence of injecting reference content rather
than a discovered fact — there is no condition to key it to. ADR
[0017](0017-a-session-start-hook-argues-the-token-ledger.md) records it as a known
weakness rather than a solved one. If it proves to be wallpaper, the fix is a
condition, not shorter wording.

None of the four writes anything into the target repository. See ADR
[0013](0013-session-state-on-disk.md) for the state directory itself.

They are written in Python, not node. Node is absent from this project's
container, and a hook its own CI cannot exercise is an unexercised path by
construction — the first draft was node and could not be tested at all.

## Consequences

- **Enforcement is now spread across three places, and the seams are where the
  bugs are.** ADR 0010 already noted that enforcement in code moves the risk to
  the seams. Adding hooks adds seams: the exclusion hook's first draft conflated
  `Grep`'s search pattern with its file glob, so the broad grep — the actual
  observed violation — was allowed. It was caught by testing the observed case
  rather than the mechanism.

- **A hook's own comparison logic is a place to get path handling wrong.** The
  exclusion match was a plain `startswith` against a root normalised with
  `lstrip("./")`, which strips a leading slash as well as a leading dot. An
  absolute root lost its slash while the listed absolute path kept one, so every
  absolute-rooted search was allowed through. It now compares segment chains, so
  all six form combinations are denied and a sibling tree sharing no chain is
  still allowed.

- **A workaround for a broken mechanism can look like good practice.** One run
  wrote each excluded path twice, absolute and relative, and that was recorded
  as an emergent behaviour worth keeping. It was compensating for the
  `lstrip` defect. With the hook independent of form, one entry per report
  suffices and the instruction was dropped rather than added. An instruction that
  works around a bug outlives the bug, so an observed agent behaviour is a
  hypothesis about a mechanism, not a confirmed win.

- **A hook can stop the assessment instead of the leak.** The inventory gate's
  first rule counted a heading bodiless if its content lived in subsections. A
  complete inventory written that way would have been refused forever. A body now
  marks every open heading above it. Where a hook's refusal blocks the main
  workflow, the cost of a false positive is total, and the rule needs a real
  artefact to test against before it ships.

- **A hook that fails open can still fail closed on the way out.** Every hook here
  documents silence on error, and all four emitted their decision with
  `json.dump(obj, sys.stdout)`, which streams chunks into the stream as it
  serialises. A write failing partway leaves a truncated object on stdout and a
  non-zero exit — the opposite of silence, and worse than a clean failure, because a
  consumer must now parse half a decision. Reproduced against `/dev/full` and
  against a reader that closes early, which yielded `{"hookSpecificOutput": {` and
  exit 1. Found by a code review of the fourth hook, where the path is routine
  rather than latent — it writes ~2.2 KB at every session start — and only then
  recognised in the three that had shipped with it. A fail direction argued in prose
  is not the same as one the code takes.

- **The first fix for that was wrong, and only CI could tell.** Serialising fully and
  then writing and flushing inside the handler looks sufficient and is not: a failed
  flush leaves the payload in `sys.stdout`'s buffer, and CPython flushes it again at
  interpreter shutdown, outside every handler, where the second failure sets exit
  status 120 whatever the hook returned. So the hook still failed closed, one layer
  further out. The working fix never touches `sys.stdout` — it writes through
  `os.fdopen(os.dup(1), "wb")`, so nothing is buffered there and the shutdown flush
  has nothing to retry.

  What makes this worth an entry rather than a commit message is where it was
  caught. The three regression tests were green in this project's devcontainer six
  times over, because Python 3.13.14 there does not reproduce the shutdown flush at
  all; the identical tests failed on the first `act` run and would have failed on a
  billed runner, as they do on CI's 3.13.15 and on 3.14. **The container is not a
  faithful oracle for a test about interpreter shutdown**, and a hook test that
  passes locally is evidence about the container, not about the hook. Where a test
  turns on interpreter or libc behaviour, the runner image is the oracle and running
  CI locally is what makes that affordable.

- **Prose still carries everything that is not an invariant**, and both skills
  are past 500 lines. An instruction nobody reaches is worth no more than one
  nobody follows, so a new mechanism that removes the need for an instruction is
  worth more than its line count suggests.
