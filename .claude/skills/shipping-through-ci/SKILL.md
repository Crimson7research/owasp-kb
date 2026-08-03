---
name: shipping-through-ci
description: Keep work moving while CI runs — watch a run to settlement keyed to a commit, decide what can start now versus what must wait for a merge, file issues at the moment of discovery, and open a branch per issue instead of queueing behind the last one. Use this whenever you push and a check is pending, have several issues open and are deciding what to pick up, are tempted to sit idle waiting on a build, or catch yourself thinking "I will file that afterwards".
---

# Shipping through CI

Three separate mistakes cost time on this repo, and they are all avoidable mechanically:

1. Reading a check status that was true about a different commit
2. Sitting idle through a 25-minute build, or worse, starting work that collides with the branch in flight
3. Discovering a problem mid-task and carrying it in your head instead of filing it

## Watch a commit, not a pull request

`gh pr checks` has reported **green from a pre-rebase commit** after a force-push. The status was
true; it described the wrong artefact. Always resolve the SHA and report which one you watched:

```bash
head=$(git rev-parse HEAD)
for i in $(seq 1 80); do
  out=$(gh api repos/<owner>/<repo>/commits/$head/check-runs \
        -q '.check_runs[]|"\(.name)\t\(.status)\t\(.conclusion // "-")"' 2>/dev/null)
  n=$(printf '%s' "$out"|grep -c .); pend=$(printf '%s' "$out"|grep -c 'queued\|in_progress')
  [ "$n" -ge 2 ] && [ "$pend" -eq 0 ] && { echo "=== settled against $head ==="; printf '%s\n' "$out"; exit 0; }
  sleep 30
done
echo "=== timed out ==="; printf '%s\n' "$out"
```

Run it in the background so the turn is not blocked.

**First ask whether CI fires at all.** `ci.yml` has a `paths-ignore` list, so a push touching only
those paths produces no checks — and "no checks, ever" is indistinguishable from "no checks yet" to
the loop above, which will sit for its full forty minutes and then report a timeout that means
nothing. Check before watching:

```bash
git diff --name-only origin/master...HEAD | grep -vE '^(\.claude/skills/|docs/decisions/)' || echo "CI will not fire"
```

If nothing survives the filter there is nothing to wait for; merge. The ignore list is narrow on
purpose — `test` asserts against `NOTICE`, `README.md`, `docs/licensing.md`, `docs/stack.md`,
`docs/kb-packs.md`, the Dockerfile, the Makefile and everything under `plugins/` — and
`test_ci_ignores_only_paths_no_test_reads` fails if an ignored path is one the suite reads, so trust
the list rather than reasoning about it each time.

**The settle condition needs both halves.** `n >= 2` guards the window where no check has registered
yet — "no checks reported" is not a pending state and not a pass, and watchers here misfired three
times by treating it as one. `pend == 0` is the actual completion test. Naming the expected check
count keeps a workflow that never started from reading as success.

**Report conclusions; do not collapse them to pass/fail.** `settled` and `passing` are different
states. A `cancelled` conclusion is settled and is neither — and with a concurrency group configured
(one run per ref) it happens routinely, because pushing a follow-up commit cancels the in-flight run
for its parent. Observed in this session: the parent commit ended `build cancelled` / `test success`,
which a watcher that reduced the run to a boolean would have reported as a failure or, worse, as a
pass on the strength of `test` alone.

So the loop above prints each check's `name`, `status` and `conclusion` and leaves the judgement to
the reader. Treat only an explicit `success` on every expected check as green.

**Before merging, compare the SHA the checks ran against to local `HEAD`.** If they differ, the green
is about something else. Two ways they differ, and only one involves a rewrite: a force-push leaves
the old status describing a commit that no longer exists, while an ordinary follow-up commit leaves it
describing a real but superseded parent. Re-watch in both cases.

## Decide what can start now

**Nothing waits on a merge.** Independent work branches off the merged base; dependent work stacks on
the open branch. Waiting is almost always a choice, and usually the wrong one.

| Situation | What to do |
|---|---|
| Next work touches different files | New branch off the merged base |
| Next work builds on an open PR | **Stack it** — see below |
| Waiting on a 25-minute image build | Start anything that is not in the build's input |
| Two agents in one working tree | **Stop.** Shared git state, not shared files, is the hazard |

That last row is from a real loss: two implementers in one worktree, one ran `git stash`, and the
other's uncommitted edits went with it. Nothing was lost only because the stash turned out to be
strictly behind `HEAD`. File-level disjointness does not protect you — `git stash`, `git checkout`
and `git reset` are global.

Ask what each artefact actually contains before assuming a dependency. One session held a branch back
because it shared files with an open PR, while a 25-minute image rebuild ran concurrently the whole
time — correctly, because the image carries only the server and the pending work was skill prose.

## Stack dependent branches; never point them at master

```
master  <=  feature-implementation  <=  feature-depends-on-previous-work
```

Branch off the parent, and set the PR base to the parent:

```bash
git checkout -b feature-depends-on-previous-work feature-implementation
gh pr create --base feature-implementation --title …
```

Pointing the child at `master` instead is the mistake. Its diff then contains the parent's changes
too, so the review cannot tell the new work from the work already under review, and every comment on
the shared lines gets made twice.

**Merge strictly bottom-up.** When the parent merges and its branch is deleted, GitHub retargets the
child's base automatically — so the chain unwinds without manual edits, and each PR's diff stays
scoped to its own change the whole way.

**One caveat with squash merges.** Squashing rewrites the parent's commits, so after the parent lands
the child still carries the originals, which no longer exist on `master`. The retarget happens but the
diff comes back inflated. Fix it before reading anything into that diff:

```bash
git fetch origin
git rebase --onto origin/master feature-implementation feature-depends-on-previous-work
git push --force-with-lease
```

Then re-check CI, because the force-push means any green status now describes a commit that is gone —
the same mistake as reading `gh pr checks` after a rebase, one section up.

## File the issue at the moment of discovery

Not at the end of the task. An issue costs two minutes and a note in your head costs the next
session.

What makes them worth reading later:

- **The evidence, quoted.** The error text, the counts, the file and line. `#45` was rewritten
  because a transcript grep showed the cap that fired was the concurrent one, not the session total
  — the quoted message settled it.
- **The failing code, inline**, where there is any.
- **Candidate fixes with an order of preference and the trade-off**, not a single asserted answer.
  Duplicating a 20 KB licence text is defensible; pretending it has no cost is not.
- **What it does not need** — no rebuild, no version bump, docs only. This is what makes an issue
  pickable later.

## Update an issue whose premise inverted

Harder discipline, and the one that pays most. Two examples from one session:

- `#59` was titled *"only 1 of 15 findings carries a remediation snippet"*, reading a low count as
  underdelivery. The resolution inverted it: most findings were not code defects, and the skill
  claiming every finding ends in code was the actual bug. Closing it silently would have left the
  wrong lesson on record.
- `#45` argued the default subagent budget was sufficient and session reuse was the problem. The
  transcripts showed the session total was never reached in any run and the concurrent cap fired
  seventeen times in the one that failed. The correction went on the issue.

A wrong issue left standing is worse than no issue, because someone will act on it. When the premise
changes, say so in a comment and say what replaced it.

## One branch per issue

Open the next branch off the merged base as soon as the previous one is merged; do not batch several
issues into one PR to save round-trips. A PR that fixes one thing can be merged the moment its checks
pass. A PR that fixes three waits for the slowest review and takes the other two hostage.

Where a fix turns out to be two things — a defect and the guard that stops it recurring — those still
belong together, because the guard is the test for the defect.

## The general form

**A status is a fact about something; check that it is a fact about the thing you care about.** That
is the same rule as `verifying-a-reload` (which copy is running) and `mutation-checking-a-test`
(whether the green means detection). Here it is: which commit was measured, and which artefact
contains the change.

## Related

`verifying-a-reload` — before testing that a merged change works, confirm the running system has it.
`mutation-checking-a-test` — a green CI run inherits every vacuous test in the suite.
