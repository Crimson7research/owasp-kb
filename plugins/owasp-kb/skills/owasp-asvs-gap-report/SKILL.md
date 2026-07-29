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

6. **Known accepted risks** — is there a risk register or deferral log?
   Without it you will re-litigate decisions already made; with it, those become
   `GAP (accepted)` rather than news.

   If the only record of accepted risk is inside a prior assessment, it is excluded like
   any other: ask the user which findings are already accepted rather than reading it.
   A verdict of `GAP (accepted)` rests on the user's statement, not on the document.

7. **Output shape** *(default: full requirement table)* — full table or gaps only?
   Audience: engineers fixing it, or a client reading it?

Record the answers in the report header. A reader must be able to see what was assessed
and what was deliberately left out.

## Process

The report runs as a fan-out, the same machinery as `owasp-asvs-verify`. You orchestrate;
the work happens in subagents so that no verdict is graded by the agent that produced it.

1. **Agree the scope** (above). This gates everything — a wrong scope wastes every agent
   dispatched after it.

   **Find prior assessments before anything else runs.** Look for existing security
   assessments of this target — `docs/security/`, files named for ASVS, audit, pentest or
   security review. List their paths, tell the user they exist, and confirm they are to be
   excluded rather than used as source material for the report you are about to produce.

   Pass that list to every agent you dispatch, and to `owasp_roster` as `excluded`. Agents
   must know these files exist and must not open them: another assessment's conclusion is not
   evidence, and an agent that reads one tends to confirm it rather than test it. Design
   documentation is *not* excluded — it is primary evidence, and documentation-class
   requirements cannot be answered without it.

2. **Build the inventory.** Dispatch `owasp-scope-inventory` once per concern —
   endpoints, middleware, identity, storage, cryptography, client surface — in parallel.
   They report what exists; none of them judges it. Their combined output is the ground
   truth every later agent works from, and it stops seventeen agents each rediscovering
   the routing table.

3. **Triage applicability yourself.** For each of the 17 ASVS chapters, decide from the
   inventory whether it `APPLIES` or is `EXEMPT`, with a specific reason. Do this
   centrally rather than dispatching it — it is one judgement over seventeen items, and
   keeping it here is what lets you produce a complete roster.

   **An exemption is a claim, not a skip.** Each one goes to a refuter in step 5.

4. **Dispatch a `owasp-chapter-orchestrator` per `APPLIES` chapter**, giving it the
   chapter id, the target level and the inventory. It pulls its own requirements and
   dispatches a finder per applicable requirement.

   **Check every returned report ends with `REPORT COMPLETE`.** Without it the agent
   was cut off — it exhausted its turns, or it backgrounded its own children and
   returned early. Both produce text that reads like an answer. Discard it and
   re-dispatch with narrower guidance, or record `INSUFFICIENT EVIDENCE`. A status
   line is not a result.

5. **Verify, exemptions first.**
   - One `owasp-exemption-refuter` per `EXEMPT` chapter. A refuted exemption returns the
     chapter to scope: go back to step 4 for it. This is a finding in its own right.
   - One `owasp-finding-verifier` per `GAP`. It returns the source→sink trace, the CWE and
     the remediation citation.
   - Escalate to a **second** verifier only where the first returned `unclear`.

6. **Accumulate findings on disk as they are confirmed**, one JSON object per line, in
   `~/.claude/owasp-kb/sessions/$CLAUDE_CODE_SESSION_ID/findings.jsonl`. Append each
   finding when its verifier returns rather than holding them all in context: a full L2
   submission is ~61,000 characters, of which `evidence` alone is 47%, and re-sending it
   to correct one verdict is the single most expensive thing you can do.

   **To correct a verdict, append a corrected line for the same `req_id`.** The later line
   supersedes the earlier one, so a correction costs ~170 characters rather than a
   resubmission — getting a verdict right stays cheap instead of becoming something to
   avoid. Do not rewrite the file.

7. **Assemble with `owasp_roster`, passing `session=$CLAUDE_CODE_SESSION_ID`** so it reads
   what you accumulated. Pass your `chapter_states` and any findings not already on disk —
   including each orchestrator's `not_applicable` entries — those are findings with an
   N/A verdict, not omissions. Dropping them re-files a determined N/A as
   INSUFFICIENT EVIDENCE. Do not tally by hand — the tool places every requirement in
   exactly one verdict, marks anything you did not report as `INSUFFICIENT EVIDENCE`, and
   tells you whether the roster is complete. If it returns `complete: false` or an error,
   fix the inputs; do not report around it.

   Pass `excluded=` the prior assessments found during scoping. A finding citing one is
   rejected, and the roster will name it.

8. **Cite the exact ASVS version** from `kb_info`.

## Output

**Write the report in numbered sections, not one file.** An assessment takes an hour and 150-odd
subagents; the report was the only stage that was not incremental, and a single 120,000-character
write depends on all of it surviving in your context until one call succeeds. That call is larger
than `owasp_checklist(level='2')`, which already proved undeliverable. For a client deliverable the
cost of losing it at the last step is the whole assessment.

Write each section to `~/.claude/owasp-kb/sessions/<session-id>/report/` as its material becomes
available -- a chapter roster when its orchestrator returns, a finding when its verifier finishes:

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

Then merge, giving the finding count `owasp_roster` reported:

```
owasp-kb-report merge --session <session-id> \
    --out docs/security/asvs-5.0.0-l2-<target>.md --expect-findings 38
```

It refuses on a duplicate number, on a count that disagrees with the roster, and on an empty
directory -- each of which would otherwise hand a client a report that looks complete. Do not
concatenate the sections yourself: re-reading forty files costs the context this exists to save, and
a dropped one would go unnoticed.

Grouped by chapter, with a per-chapter count of met / gap / not applicable — this is the
client-readable artefact — plus the full table: requirement id, level, verdict, evidence,
CWE, remediation.

Every requirement appears exactly once, in one of six states. Do not collapse the three
uncertain ones into `MET` or `GAP`; carrying them through is the point:

| Verdict | Meaning |
|---|---|
| `MET` | Control present and read |
| `GAP` | Control absent or inadequate, verified |
| `GAP (unconfirmed)` | Reported, but verification was inconclusive twice |
| `N/A (verified)` | Chapter **or requirement** exempt, and a refuter searched and returned `exemption_holds` |
| `N/A (unverified)` | Chapter **or requirement** exempt, refutation inconclusive |
| `INSUFFICIENT EVIDENCE` | Could not be determined |

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

**Every finding gets one**, and it ends in code. If the corpus has nothing to cite, that is a reason
to label the source — never a reason to omit the fix.

**Show the remediation as a snippet, written against this repository.** Prose steps describe work;
a snippet shows it. "Extend the property enum with encryption flags and have the mapper emit them"
leaves the client to guess at the shape you had in mind — the code says it in four lines and is
checkable against the file it patches:

```js
// lib/session-cookie.ts — new
export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
} as const
```

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

These get a section too, and they are among the most useful entries in the report. They are
recorded `INSUFFICIENT EVIDENCE` rather than `MET`: refuting the reported defect is not the same as
establishing the control is adequate, and nobody produced that finding. Their Recommendation slot
becomes *what would need to be assessed to reach `MET`*.

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
