---
name: owasp-asvs-gap-report
description: >
  Use when producing an OWASP ASVS compliance report, gap analysis, security
  requirements baseline, control matrix, or evidence matrix for an application
  at a target ASVS level, including when asked what is needed to reach ASVS L1,
  L2 or L3.
---

# ASVS gap report

Produce a complete, citable gap analysis at a target ASVS level.

## Before starting: agree the scope

A gap report especially needs scope and level agreed before starting — completeness only
means something once the boundary is fixed. Ask these in **one message**, with the
defaults marked, so the user can reply "defaults except scope: firmware/". If they decline
to answer or say to just get on with it, proceed on the defaults — but **state every
assumption in the report header** so it is visible and disputable rather than silent.

1. **Scope** — which subtrees are in scope? List the candidates you can see. Anything
   excluded gets stated as excluded, never silently unexamined.

2. **Target level** — levels are cumulative:

   | Level | Requirements | Cost | Justified when |
   |---|---:|---|---|
   | L1 | 70 | fastest | Any application. Opportunistic attackers, low-value data. A floor, not a target. |
   | **L2** *(default)* | **253** | ~3.6× L1 | Anything handling personal data, credentials or transactions. Most systems should target this. |
   | L3 | 345 | ~4.9× L1 | Payments, health, safety-critical. Expensive and rarely justified below that bar. |

3. **Deployment context** — where does this run and who can reach it? Internet-facing,
   LAN-only, air-gapped, physical access assumed? This is what makes a NOT APPLICABLE
   verdict defensible rather than a guess.

4. **Trust boundaries** — which interfaces accept data you do not control? Establishing
   these first turns "is this requirement applicable" from a judgement call into a lookup.

5. **Evidence depth** *(default: code and configuration)* — is configuration and
   documentation acceptable evidence, or code only?

6. **Execution** *(default: `none` — static evidence only)* — may an agent run code to
   settle a claim? This is the SAST/DAST line and it is the user's call, not yours. Three
   answers:

   | Answer | What an agent may do |
   |---|---|
   | `none` | Nothing runs. Every verdict rests on reading. |
   | `local` | Probes may build and execute in a scratch directory. No network at all. |
   | `loopback` | As `local`, plus binding and contacting `127.0.0.1`. Never a real host. |

   **Write the answer to `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/execution`**,
   one word, before dispatching anything, and state it in every agent prompt you send. A
   missing file means `none`: an assessment that never asked is an assessment that may not
   run anything.

   Saying `none` is a legitimate answer and costs less than it sounds. A claim that could
   only have been settled by running something is reported as argued rather than
   demonstrated, and says so.

   Saying `loopback` is what a reproduction needs, and it is a real authorisation: probes
   execute on the machine running this assessment. One run reached a live public IP before
   anyone had agreed that running anything was acceptable — which is the failure this
   question exists to prevent, and why the default is `none`.

7. **Known accepted risks** — is there a risk register or deferral log?
   Without it you will re-litigate decisions already made; with it, those become
   `GAP (accepted)` rather than news.

   If the only record of accepted risk is inside a prior assessment, it is excluded like
   any other: ask the user which findings are already accepted rather than reading it.
   A verdict of `GAP (accepted)` rests on the user's statement, not on the document.

8. **Output shape** *(default: full requirement table)* — full table or gaps only?
   Audience: engineers fixing it, or a client reading it?

Record the answers in the report header. A reader must be able to see what was assessed
and what was deliberately left out.

## Process

The report runs as a fan-out, the same machinery as `owasp-asvs-verify`. You orchestrate;
the work happens in subagents so that no verdict is graded by the agent that produced it.

0. **Declare the stages before dispatching anything.** Create these nine tasks with `TaskCreate`,
   then mark each `in_progress` when you enter it and `completed` when you leave it. Set the
   dependencies with `TaskUpdate(addBlockedBy=...)` so the ordering is declared rather than
   described.

   | # | subject | activeForm | blockedBy |
   |---|---|---|---|
   | 1 | Agree scope | Agreeing scope | — |
   | 2 | Record exclusions | Recording exclusions | 1 |
   | 3 | Build inventory | Building the inventory | 2 |
   | 4 | Triage applicability | Triaging applicability | 3 |
   | 5 | Refute exemptions | Refuting exemptions | 4 |
   | 6 | Assess chapters | Assessing chapters | 4 |
   | 7 | Verify findings | Verifying findings | 6 |
   | 8 | Assemble roster | Assembling the roster | 5, 6, 7 |
   | 9 | Write report | Writing the report | 8 |

   `Refute exemptions` and `Assess chapters` both hang off `Triage applicability` rather than
   chaining, because step 3 dispatches both groups at once. The graph should say what the run
   does, not something tidier that the run then visibly violates.

   Put a count in the subject of the three long stages as returns arrive — `Assess chapters
   (3/12)`. Those are where the hours go. The other six complete in one action, where a count
   is noise.

   **This is not a recovery mechanism.** The dispatch ledger in step 2 is: it is per-agent, it
   is on disk, and it survives a compaction this list is not known to survive. Keep both. They
   answer different questions — this one is "which stage are we in", for whoever is watching.

   Nothing checks this list. A run that stops updating it produces a stale display and a correct
   assessment: `verification_complete`, the inventory gate and the exclusion hook are what gate
   correctness, and none of them depends on this.

1. **Agree the scope** (above). This gates everything — a wrong scope wastes every agent
   dispatched after it.

   **Find prior assessments before anything else runs.** Look for existing security
   assessments of this target — `docs/security/`, files named for ASVS, audit, pentest or
   security review. List their paths, tell the user they exist, and confirm they are to be
   excluded rather than used as source material for the report you are about to produce.

   **Write the paths, one per line, to
   `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/excluded`.** A `PreToolUse` hook reads
   that file and refuses any `Read`, `Grep` or `Glob` that would put one of them in front of an
   agent. Without the file the hook has nothing to enforce and silently allows everything — the
   list is what arms it, and it is scoped to this session so no other session is affected.

   Then pass the same list to every agent you dispatch, and to `owasp_roster` as `excluded`.
   The three are different controls: the hook stops the read, the prompt tells an agent why,
   and the roster rejects a finding that cites one. A previous run had a finder grep an
   excluded report and quote the hit, and only the orchestrator's diligence caught it.

   Agents must know these files exist and must not open them: another assessment's conclusion
   is not evidence, and an agent that reads one tends to confirm it rather than test it. Design
   documentation is *not* excluded — it is primary evidence, and documentation-class
   requirements cannot be answered without it.

2. **Build the inventory.** Dispatch `owasp-scope-inventory` once per concern —
   endpoints, middleware, identity, storage, cryptography, client surface — in parallel.
   They report what exists; none of them judges it. Their combined output is the ground
   truth every later agent works from, and it stops seventeen agents each rediscovering
   the routing table.

   **Write the concern list, one per line, to
   `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/concerns` before those agents go out**,
   then merge each return into
   `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/inventory.md` as it arrives — headed
   `# Scope inventory — factual, no verdicts`, then what the target is, the trust boundaries,
   then one section per concern with file and line references. One document rather than five
   per-concern files: it is what triage actually reads, and five would need reassembling first.

   A `PreToolUse` hook refuses an `owasp-chapter-orchestrator` or `owasp-exemption-refuter`
   dispatch until every concern on that list has a section with something under it. The concern
   list is what arms the gate, so writing it after the returns leaves it inert for the run it was
   meant to gate. Nothing else can see this stage — `owasp_roster` counts verdicts and the
   inventory produces facts — and one run had four of five inventory agents return, then triaged
   all seventeen chapters over the hole. A concern that found nothing still gets a section saying
   so: "no client-side surface exists in this target" is a survey result, and an empty heading is
   not.

   **Keep a dispatch ledger at
   `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/pending.txt`**, updated as agents go out
   and return. It is for you rather than for the client, and it survives a compaction your
   context does not:

   ```
   INVENTORY dispatched: endpoints middleware identity storage client-surface
   INVENTORY returned:   endpoints middleware identity storage
   PENDING: none - all 12 applicable chapters dispatched
   DISPATCHED: V1 V2 V4 V6 V7 V8 V11 V12 V13 V14 V15 V16
   RETURNED: V6 V14
   EXEMPT verified: V3 V5 V9 V10 V17
   GAPS AWAITING VERIFIER: V6.3.3; V14.1.1 V14.1.2 V14.2.2 V14.2.4 V14.3.1
   ```

   The last line names the queue that starves, and the ledger is only ever a record: the run that
   wrote this one tracked that queue correctly and still lost 35 verifier dispatches to the
   concurrency limit, which is why `verification_complete` is the gate and this is not.

3. **Triage applicability yourself, then dispatch both groups at once.** For each of the 17
   ASVS chapters, decide from the inventory whether it `APPLIES` or is `EXEMPT`, with a
   specific reason. Do this centrally rather than dispatching it — it is one judgement over
   seventeen items, and keeping it here is what lets you produce a complete roster.

   **An exemption is a claim, not a skip**, and its refuter goes out here, in the same breath
   as the orchestrators. A refuter needs your triage decision and the inventory and nothing
   else — it never depended on an orchestrator, and holding it back until every applicable
   chapter had finished is what left a refuted exemption returning its chapter to scope with
   nothing left to run it in.

   - `APPLIES` → one `owasp-chapter-orchestrator`, carrying the chapter id, the target level,
     the inventory and the excluded-material list.
   - `EXEMPT` → one `owasp-exemption-refuter`, carrying the same excluded-material list. An
     `exemption_refuted` returns that chapter to scope: it becomes an applicable chapter with
     its own orchestrator and runs exactly like the rest — and the reversal is itself a finding,
     worth stating in the report rather than silently re-scoped. An `exemption_holds` finishes
     that chapter's pillar outright: write its `120_exemptions` line and its
     `2NN_requirement_roster` section then, because every requirement in it is already settled
     as `N/A (verified)`.

   **This is the last decision taken across all seventeen chapters.** After it, no chapter
   waits for another.

4. **Run each chapter to completion on its own clock.** A chapter is a pillar, not a row
   marched through a stage: when V6's orchestrator returns, everything below happens for V6
   while V14's finders are still running. Seventeen chapters taken through one stage at a time
   is what wrote all seventeen roster sections in a single minute at the end of a two-hour run.

   For each chapter, as its orchestrator returns — and if several return in the same batch, take
   them one at a time, writing each chapter's section as you read its result rather than after
   reading all of them:

   - **Check the report ends with `REPORT COMPLETE`.** Without it the agent was cut off — it
     exhausted its turns, or it backgrounded its own children and returned early. Both produce
     text that reads like an answer. Discard it and re-dispatch with narrower guidance, or
     record `INSUFFICIENT EVIDENCE`. A status line is not a result.
   - **Dispatch one `owasp-finding-verifier` per `GAP` in that chapter — you dispatch it, not
     the orchestrator.** It returns the source→sink trace, the CWE and the remediation
     citation. Independence here is structural rather than instructed: you hold only the
     orchestrator's condensed JSON — `req_id`, `verdict`, `evidence`, `file`, `line` — so a
     finder's argument cannot reach the verifier through you. The orchestrator does hold the
     finder's full text, so handing it this dispatch would trade the guarantee for a promise.
   - **Escalate to a second verifier only where the first returned `unclear`.** That
     escalation belongs to this chapter, not to a later sweep.
   - **Append that chapter's findings to disk as each verifier returns**, per the paragraphs
     below.
   - **Write that chapter's `2NN_requirement_roster` section once its verifiers have
     returned — immediately, if the orchestrator reported no gaps.** Its verdicts are settled at that point
     and not before: on one run 62 gaps were reported and 32 of them refuted, so a section
     written when the orchestrator returned would have been wrong for more than half its gap
     rows.

   Each chapter releases its own small batch of verifiers as it becomes ready, rather than every
   chapter releasing together. The cap is `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS` — 20 per
   session — either way; what this avoids is the burst that had seventeen dispatches refused in
   one run.

   **Accumulate findings on disk as they are confirmed**, one JSON object per line, in
   `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/findings.jsonl`. Append each
   finding when its verifier returns rather than holding them all in context: a full L2
   submission is ~61,000 characters, of which `evidence` alone is 47%, and re-sending it
   to correct one verdict is the single most expensive thing you can do.

   **To correct a verdict, append a corrected line for the same `req_id`.** The later line
   supersedes the earlier one, so a correction costs ~170 characters rather than a
   resubmission — getting a verdict right stays cheap instead of becoming something to
   avoid. Do not rewrite the file.

   **A verifier that returns `refuted` still produces a line.** Its verdict is
   `INSUFFICIENT EVIDENCE (gap refuted)`, its `trace` is the verifier's `mitigations_present`
   and `mitigation_location`, and its `file`/`line` are that location. Dropping the line re-files
   the requirement as though no finder ever looked at it. If the verifier named no location,
   record `mitigations_present` alone as the `trace` — the roster requires a trace, not a
   location, and recording plain `INSUFFICIENT EVIDENCE` instead, for want of one, lands in
   the verdict that also means nobody looked: it carries a `finding_id`, so it never appears
   in `unassessed`, is not counted in `unverified`, and leaves `verification_complete` true.

5. **Assemble with `owasp_roster`, passing `session=$CLAUDE_CODE_SESSION_ID`** so it reads
   what you accumulated. Pass your `chapter_states` and any findings not already on disk —
   including each orchestrator's `not_applicable` entries — those are findings with an
   N/A verdict, not omissions. Dropping them re-files a determined N/A as
   INSUFFICIENT EVIDENCE. Do not tally by hand — the tool places every requirement in
   exactly one verdict, marks anything you did not report as `INSUFFICIENT EVIDENCE`, and
   tells you whether the roster is complete. If it returns `complete: false` or an error,
   fix the inputs; do not report around it.

   Pass `excluded=` the prior assessments found during scoping. A finding citing one is
   rejected, and the roster will name it.


6. **Do not write the report while `verification_complete` is false.** The roster returns
   two different facts and they are easy to conflate: `complete` means every requirement
   carries a verdict, and `verification_complete` means every asserting claim met its
   adversary. A roster can be `complete: true` with most of its gaps unchecked — one run
   shipped a report with 35 of 51 gaps unverified, and the field said complete because
   every requirement had been placed.

   Two fields say what is outstanding, and they name different stages:

   - **`unassessed`** — requirement ids in an applicable chapter that **no finder reported
     on at all**. These are `INSUFFICIENT EVIDENCE`, and so is a finder's own "I looked and
     could not determine" — two different facts sharing one verdict. One means the
     assessment is incomplete; the other is a legitimate result. Dispatch a finder for each.
   - **`unverified`** — asserting claims that never met their adversary, counted per
     verdict. Dispatch a verifier for each `GAP (unconfirmed)` and a refuter for each
     `N/A (unverified)`.

   Loop: dispatch what those two name, append the results, call `owasp_roster` again, and
   repeat until `verification_complete` is true. It covers both stages, so a requirement
   nobody looked at blocks the report exactly as an unchecked gap does. If any of those
   dispatches moves a verdict in a chapter whose `2NN_requirement_roster` section is already on
   disk, rewrite that section — unlike `findings.jsonl`, a section is a file, so correcting it
   is an overwrite rather than an append.

   **A dispatch that errors is not a verdict.** If subagents fail to spawn — a concurrency
   or session limit — that is a transient failure, not a finding. Dispatch fewer at once and
   retry rather than accepting the downgrade: `GAP (unconfirmed)` is the honest record of a
   claim nobody tested, and it is *also* what giving up looks like, so the two are
   indistinguishable in the output.

   Only when a shortfall genuinely cannot be cleared do you proceed — and then **say so in
   the Results section**, with the count and the reason. A reader cannot otherwise tell an
   unverified gap from one that was tested.

7. **Cite the exact ASVS version** from `kb_info`.

## Output

**Write the report in numbered sections, not one file.** An assessment takes an hour and 150-odd
subagents; the report was the only stage that was not incremental, and a single 120,000-character
write depends on all of it surviving in your context until one call succeeds. That call is larger
than `owasp_checklist(level='2')`, which already proved undeliverable. For a client deliverable the
cost of losing it at the last step is the whole assessment.

Write each section to `~/.claude/owasp-kb/sessions/<session-id>/report/` as its material becomes
available -- a chapter roster when that chapter's verifiers return, a finding when its verifier
finishes:

```
100_title.md
101_summary.md            scope and assumptions, results, cross-cutting root causes
110_trust_boundaries.md
120_exemptions.md
201_requirement_roster_v1.md ... 217_requirement_roster_v17.md
300_findings_intro.md
301_finding_1.md ... 3NN_finding_N.md
400_refuted_findings_intro.md
401_refuted_finding_1.md ...
```

The numeric prefix carries the order. Findings go in the **300 block** and refuted ones in the
**400 block**, because the merge counts the 300s against the roster.

**Write each section at the earliest point its material exists.** The prefix decides where a
section lands in the report, so writing order does not matter — which means a section never has
to wait for its neighbours. Measured on a real run, the report took 17 minutes of the 64 to
write, almost all of it after verification had finished, because the rosters were batched into
one moment and the findings were written one after another at the end. None of that had to be
serial.

| Section | Can be written as soon as |
|---|---|
| `100_title` | scope is agreed — before any agent is dispatched |
| `110_trust_boundaries` | the inventory returns |
| `120_exemptions` | **each** refuter returns — per exempt chapter, not one batch |
| `2NN_requirement_roster_vNN` | **that chapter's** verifiers return — or, for a chapter that stays exempt, its refuter — one per chapter, not one batch |
| `300_findings_intro`, `400_refuted_findings_intro` | the first finding of that kind exists |
| `3NN_finding_N`, `4NN_refuted_finding_N` | **that finding's** verifier returns |
| `101_summary` | last — it quotes the roster's final counts, so it cannot be written until `verification_complete` |

Only the summary genuinely has to come last. Everything else can be written while other agents
are still running, and a run interrupted late then has most of its report already on disk.

Then merge, giving the finding count `owasp_roster` reported:

```
owasp-kb report merge --session <session-id> \
    --out docs/security/asvs-5.0.0-l2-<target>.md --expect-findings 38
```

It refuses on a duplicate number, on a count that disagrees with the roster, and on an empty
directory -- each of which would otherwise hand a client a report that looks complete. Do not
concatenate the sections yourself: re-reading forty files costs the context this exists to save, and
a dropped one would go unnoticed.

**Name the report so it cannot be confused with the one you excluded.** Two assessments of one
target at one level otherwise differ only by their filename date, and the excluded report is the
thing a client is most likely to reach for by mistake:

```
--out docs/security/asvs-5.0.0-l2-<target>-independent-<YYYY-MM-DD>.md
```

Then say in `100_title.md` which priors were excluded and that they were never opened. Without that
sentence a reader assumes this assessment built on them, which is the opposite of what happened, and
two reports of one target stop being comparable.

**State the root-cause reduction as a number in `101_summary.md`,** not only as a list:

> 51 gap entries are not 51 independent problems. They reduce to five.

Then the five, each naming the requirements it accounts for. The ratio is what tells a client
deciding where to start that the work is five changes and not fifty-one; the list alone reads as
five more items on the pile.

Grouped by chapter, with a per-chapter count of met / gap / not applicable — this is the
client-readable artefact — plus the full table: requirement id, level, verdict, evidence,
CWE, remediation.

Every requirement appears exactly once, in one of seven states. Do not collapse the four
uncertain ones into `MET` or `GAP`; carrying them through is the point:

| Verdict | Meaning |
|---|---|
| `MET` | Control present and read |
| `GAP` | Control absent or inadequate, verified |
| `GAP (unconfirmed)` | Reported, but verification was inconclusive twice |
| `N/A (verified)` | Chapter **or requirement** exempt, and a refuter searched and returned `exemption_holds` |
| `N/A (unverified)` | Chapter **or requirement** exempt, refutation inconclusive |
| `INSUFFICIENT EVIDENCE` | Could not be determined |
| `INSUFFICIENT EVIDENCE (gap refuted)` | A gap was reported and a verifier disproved it; nothing positive was established about the control |

Every `GAP` carries a remediation citation — the finder's mapped guidance document at minimum,
a precise `doc_key#anchor` with a `remediation_quote` where the verifier navigated to and read a
section. A `GAP` with neither is incomplete, so say so rather than writing remediation from your
own knowledge.

**Show where a CWE came from.** `owasp_roster` returns `cwe_corpus`, the ids OWASP's mapping
carries for that requirement. Where your cited `cwe` is not among them, say so — the mapping is
per requirement and a finding is per defect, so a more specific id is often right, but a reader
must be able to tell which is which:

`CWE-789 — model-assigned; mapping carries CWE-120 for this requirement`

Where `cwe_corpus` is empty, say the mapping is silent rather than leaving it blank.

Where you cite an id the mapping does not carry, `cwe_get` it and give the weakness **name**
beside the id — a reader cannot judge `CWE-789` but can judge *Memory Allocation with
Excessive Size Value*. Where the mapped entry is `Obsolete` or is a Category rather than a
weakness, say that: it is the reason a more specific id is right, and `cwe_get` reports both.

`CWE-798 Use of Hard-coded Credentials — model-assigned; mapping carries CWE-320 Key Management
Errors, which is an Obsolete Category and lists CWE-798 among its members`

Keep the id itself bare in the roster payload. `cwe_get` is for the report text; `owasp_roster`
matches `cwe` against `cwe_corpus` and dedupes on it, and an id with a name appended matches
nothing.

**Show whether guidance was read.** A `remediation` with a `remediation_quote` is a section an
agent navigated to and read. One without is the requirement-level mapping. Both are citations from
the knowledge base, but only one is specific, so mark it with **`§`**:

`Authentication_Cheat_Sheet#password-storage §` — read, and quoted in the finding detail
`Authentication_Cheat_Sheet` — the requirement-level mapping; no section was read

Define the marker where the reader meets it, so a glyph never appears unexplained:

> Remediation citations marked **§** are sections an agent navigated to and read, and carry a
> verbatim quote in the finding detail. Citations without **§** are the requirement-level mapping
> only — the document is the right one, but no specific section was read.

**An unmarked citation is not a defect to drive to zero.** The mapping is coarse and 13 of the 345
requirements have no guidance edge at all, so some proportion will always be document-level. The
marker exists to make that visible, not to push the count up — an agent that reads an unmarked
citation as a failure goes hunting for a section that does not exist.

Report the total requirement count and confirm the table has that many rows.
`owasp_roster` now supplies both the count and the per-verdict tally, so this is a fact
you report rather than a claim you make.

## Detail sections

The grouped table is the summary and stays complete — every requirement, every verdict. Below it,
add one detail section per **verified `GAP`** and per **finding a verifier refuted**. Those are the
rows a client will actually work from. `GAP (unconfirmed)` and the rest stay table rows, which is
what keeps the artefact finite: a 97-gap report would otherwise run to thousands of lines.

Each section follows this shape:

    ## Finding 7 — Staged credentials survive disconnect — `GAP`

    | | |
    |---|---|
    | **Covers** | V7.3.1 (L2), V7.4.1 (L1) |
    | **Location** | `src/net/connection_handler.c:136` |
    | **CWE** | CWE-613 — matches the mapping |
    | **Root cause** | #3 — termination is not implemented anywhere |
    | **Technical severity** | High — reasoning below |

    ### Requirement
    > **ASVS 5.0.0 V7.4.1** (L1) — <the requirement text, verbatim from owasp_checklist>

    ### Description
    <what the defect is, in prose>

    **Flow — how the value becomes reachable:**
    <a rendered flow block, source to sink>

    <a code block showing the offending lines, each one marked>

    **Reachability confirmed:** <the query you ran, and what it showed>

    ### Risk
    ### Technical risk assessment
    ### Recommendation
    <the principle, with its provenance>
    <a code block showing the fix, written for this repository>
    ### References

**The verdict goes in the heading.** A run can produce 25 verified gaps and 72 unconfirmed ones;
rendering them alike makes three quarters of the report read as confirmed — which for a client
artefact is the difference between a finding and a suspicion.

**`Covers` lists every requirement.** Findings sharing a `(file, line, cwe, verdict)` merge, so one defect
routinely covers several, and the heading cannot be an ASVS id.

**`Root cause` points back to the cross-cutting section.** Without it a client fixes 97 symptoms
instead of the handful of decisions underneath them.

**Omit the CWE row** when you have no id and `cwe_corpus` is empty. Coverage is 204/345, so absence
is ordinary; a blank field reads as an oversight.

### Description carries the flow, and shows the code

Two blocks, both rendered, not described. Prose about a trace is not a trace, and a `file:line`
reference is not a code snippet — a client who has to open the file to see the defect has been
handed a lookup, not a finding, and will say so.

**The flow block.** For injection this is a genuine source-to-sink taint path. For a *missing*
control there is no tainted data, so it is the attack path from the absent control to the reachable
effect. Either is fine; omitting it is not, because a `GAP` with no path is an assertion and a
client will treat it as one.

```
create()                                     app/actions/session.ts:6
  └─ cookieStore.set('session_id', …)                          :9   ← no options object
        └─ Set-Cookie: session_id=…                                 ← no HttpOnly, no Secure
              └─ document.cookie readable by any script in the origin
                    └─ SINK: any XSS or malicious dependency exfiltrates a valid session
```

**The code block.** Show the actual source, and mark the offending lines so the defect is visible
without counting lines. A caret and the line number under the exact column is enough:

```js
export async function create(data) {
  const cookieStore = await cookies()

  cookieStore.set('session_id', 'example')
  //              ^ :9  no options object at all — no HttpOnly, no Secure, no SameSite

  cookieStore.set('session_id', 'example', { secure: true })
  //              ^ :11 Secure present, HttpOnly still absent
}
```

Quote enough surrounding code to make it readable and no more. Elide with `…` rather than pasting a
whole function, and keep the real line numbers — a snippet renumbered from 1 cannot be checked
against the file, and checking it is the first thing a developer will do.

**When there is no path, the code block carries the finding alone.** Plenty of real findings are a
single blameable line — a missing flag, a wrong constant, a disabled check — with no source and no
sink. Do not manufacture a flow for those. Say the defect is a single line, drop the flow block, and
let the marked code block do the work. What you must not do is drop *both* and leave only a
`file:line` reference.

**Then say how you know the control applies here at all.** "Is this even applicable to us" is the
first question you will get back. Name the query you ran and what it returned — `grep -rn
"session_id" app/ --include=*.tsx returns no client-side read, so no functionality depends on script
access` is checkable; "the cookie is not read by scripts" is not.

### Technical risk assessment

Score what the code shows. Give the CVSS vector and the reasoning per metric, and **flag every
metric resting on an assumption the code cannot settle** — Confidentiality and Integrity usually
depend on what a compromised credential actually grants, which is a business input you do not have
and must not silently invent.

State what would move the number. "8.1, or 5.4 if that session only carries anonymous cart state"
is a score the client can challenge and correct from their own knowledge; a bare 8.1 is not. Say
when a weakness is conditional — needing a second flaw to exploit — and why you scored it as you
did regardless.

Do not score temporal or environmental metrics. Both need deployment facts the repository does not
contain.

### Recommendation, with its provenance stated

**Every finding gets one.** If the corpus has nothing to cite, that is a reason to label the source
— never a reason to omit the fix.

**Show the remediation as code when the defect is in the code**, written against this repository.
A wrong constant, a missing flag, an options object assembled per call site — "extend the property
enum with encryption flags and have the mapper emit them" leaves the client to guess at the shape you
had in mind, where the code says it in four lines and is checkable against the file it patches:

```js
// lib/session-cookie.ts — new
export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
} as const
```

**Where the defect is not in the code, there is no code to show, and inventing some makes the report
worse.** Three cases come up repeatedly, and each has its own concrete answer:

- **Configuration** — a build flag, a framework setting, a `sdkconfig`/`web.config`/`values.yaml`
  key. Name the setting and the value it should hold. That is exact and checkable without being code.
- **Deployment or an external control** — a TLS policy, a firewall rule, a WAF signature, an IAM
  binding. Name the control and where it lives. You cannot patch it from this repository, and a
  snippet implying you could sends the reader to the wrong file.
- **A higher-level structural failure** — "no authentication on the provisioning service" has no
  four-line patch. It gets the ordered sequence described below.

The harm in forcing a snippet onto these is specific: it misrepresents the size of the work, and a
client who plans against a patch that does not exist finds out late. Judge which kind the defect is,
and let that decide whether code appears.

Use the real identifiers, paths and types from the target. A snippet that compiles against an
imagined API is worse than none, because it looks verified and a client will try to apply it.

**Where the root cause is that something is assembled ad hoc per call site, patch the class, not the
site.** Fixing one call site leaves the next to regress, so show the shared helper and the call that
uses it — that is what removes the finding rather than the instance.

State the provenance every time, *including* when it is corpus-quoted. The principle may be OWASP's;
the code you write is always yours, and marking only the citation lets your snippet borrow its
authority.

- **Corpus-quoted** — quote the section, cite `doc_key#anchor` and the pinned version, and mark any
  snippet you wrote as yours rather than OWASP's.
- **Principle cited, implementation recalled** — the common case, where the corpus covers the idea
  but not this framework's API. Say so plainly: *implementation from model training data, not the
  OWASP corpus; verify against current documentation before implementing.*
- **No corpus coverage** — lead with the warning, not a footnote: *⚠ from model training data, not
  the OWASP corpus.* Name the `owasp_search` query that returned nothing, and say it may be
  hallucinated and must be verified rather than cited.

Recording the empty query matters: it is evidence the gap is in the corpus rather than in the
assessment, and it lets someone check whether a better query would have found something. Never
synthesise an anchor for a section that does not exist — `owasp_roster` rejects one that does not
resolve, and a reader cannot tell a guessed anchor from a real one.

**Prefer a working pattern already in the target repository** over anything reconstructed. If the
codebase solves this correctly somewhere else, cite that first — it is better provenance than any
tier, and it tells the client the fix is already proven in their own codebase.

Where no minimal fix exists, because the finding is architectural, give an ordered sequence and say
which requirements become *implementable* once it is done. **Say plainly that no snippet is offered
and why** — "no implementation snippet is offered; the existing `compiler_key_id` path in this
repository is a better reference than anything reconstructed" is an answer. Silently dropping the
code block is not, because a client cannot tell a considered omission from a forgotten one. Do not
invent a snippet that misrepresents the work involved — a client planning against a one-line fix for
a structural change will plan wrong.

### Findings a verifier refuted

These get a section too, and they are among the most useful entries. Record them
`INSUFFICIENT EVIDENCE (gap refuted)`, never `MET`: refuting the reported defect is not the same
as establishing the control is adequate, and nobody produced that finding.

The verifier returns `mitigations_present` and `mitigation_location` on this branch. Write both
into the finding's `trace` and put the mitigation's `file` and `line` on the finding — the roster
rejects this verdict without a trace, because a verdict nothing checked is a label anyone can
apply. Their Recommendation slot becomes *what would need to be assessed to reach `MET`*.

## Rules

- Applicability, verdicts and remediation are the dispatched agents' job, not yours: the
  inventory agents report facts only, chapter orchestrators and finders return the
  per-requirement verdict, and refuters and verifiers are the only agents that overturn an
  exemption or a reported gap. Your job is scope, chapter triage, dispatch and assembly —
  never re-deriving a verdict a subagent already produced, and never answering from memory
  in its place.
- The finder and verifier reach the knowledge base directly for every claim they make:
  `owasp_checklist` for requirement text and ids, `owasp_related` for the CWE and guidance
  links, `owasp_outline` and `owasp_get` for the remediation section itself.
  Do not answer from memory at any stage — every id, requirement text and remediation
  citation must trace back to a tool call.
- A `GAP` without a remediation citation is incomplete. The finder attaches the mapped guidance
  document as a matter of course; the verifier can replace it with a precise section citation and
  a `remediation_quote` proving they read it. If a `GAP` has neither, say so rather than writing
  remediation from your own knowledge.
- Levels are cumulative: at L2 that is 253 requirements (every L1 requirement plus every
  L2 one), not the 183 tagged L2.
- State that level counts come from the pinned ASVS release, so a future release may shift
  them.
- CWE coverage is partial — 204 of 345 requirements — because upstream publishes only a
  bleeding-edge mapping. `owasp_related` returns a note saying so when a result is empty.

## If the knowledge base is unreachable

Say so explicitly and stop. Do not produce a report from recalled requirements — a
compliance artefact with unverifiable ids is a liability.
