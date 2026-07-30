---
name: mutation-checking-a-test
description: Break the thing a new test guards and watch it fail, before believing the test works. Use this whenever adding or editing an assertion, writing a test for a skill or agent prompt, pinning a constant, reviewing someone else's new test, or reading a green suite as evidence that a fix landed. A test that has never been seen to fail is not evidence of anything, and in this repo a passing new test has been wrong more often than a failing one.
---

# Mutation-checking a test

A new test passing tells you two things are consistent. It does not tell you the test can detect
inconsistency. Those are different facts, and in this repo they have come apart repeatedly: **six
tests have shipped that could not fail**, three of them suggested by me during review.

The check is three lines of shell and takes a few seconds. Skipping it is how a test becomes
decoration.

## The procedure

```bash
cp <file> /tmp/m.bak                      # 1. save
<break the thing the test guards>         # 2. mutate
grep -c "<what you removed>" <file>       # 3. confirm the mutation took — expect 0
<test command>                            # 4. expect RED
cp /tmp/m.bak <file>                      # 5. restore
<test command>                            # 6. expect GREEN — baseline back
```

Steps 3 and 6 are the ones people drop, and both have cost real time here.

**Step 3 — confirm the mutation took.** A mutation that silently failed to apply looks exactly like
a test that cannot fail. Twice in one session a Python patch script aborted on a stale anchor, wrote
nothing, and the mutation run came back GREEN. The conclusion "this test is vacuous" was wrong both
times; the test did not exist yet. `grep -c` on the string you removed costs nothing and
distinguishes them.

**Step 6 — confirm the baseline.** Without it you cannot tell a working mutation from a tree you
broke on the way. Related: `cp -a`ing the source to a scratch directory does **not** isolate a
mutation when an editable install still resolves to the original — assert the module resolves where
you think before trusting the run.

## Mutate the guarded thing, not the test

Delete the phrase from the SKILL.md, flip the constant in the source, remove the field from the
response. If the only way to make the test fail is to edit the test, it is asserting on itself.

## Shapes that cannot fail

Every one of these shipped here and had to be rewritten.

| Shape | Why it passes regardless |
|---|---|
| `@parametrize` over the constant under test | the expectation is computed from the thing being checked — "a cap pinned to itself" |
| `"chapters": [] or [...]` in a mutation | `or` returns the non-empty list, so the mutation is a no-op |
| assertion on a `[:5]`-truncated message | the part that carries the meaning was cut before comparison |
| patching an `except` branch that never runs | the mutation is unreachable, so nothing changes |
| substring assertion on generated text | `"CWE" in notice` passes on a NOTICE that never attributes CWE, because the substring occurs in `LICENSE-CWE` |
| `assert flatten(x)` with no content check | any non-empty return satisfies it |
| fixtures built from the constant they verify | both sides move together |

The common thread: **the assertion and the thing asserted share a source.** When mutation comes back
green, look for that shared source before concluding the code is unfalsifiable.

## What to assert for prose in skills and agents

Prose tests are the ones most likely to be vacuous, because a long document contains almost any
short string you might look for.

- Assert the **specific sentence**, not a keyword. `"Show the remediation as code when the defect is
  in the code"` is checkable; `"remediation"` is not.
- Assert the **counter-case too**. A rule asserted alone reads as unconditional: the code-remediation
  rule needed its three non-code cases (configuration, deployment, structural) pinned separately,
  or an agent applies it everywhere — which was the defect being fixed.
- Put the **reason in the assertion message**, naming the run that produced the bad output. That is
  what stops the next person deleting the test as noise.

## When all-green is the finding

If a batch of mutations all come back green, the harness is broken, not the code. Check in this
order: did the mutation apply, did the test run at all, is the test collecting the file, and is the
module under test the one being imported.

## The general form

**A test's value is the failure it can produce, and you have not measured that until you have seen
it.** Green is a claim about consistency between two things; only red is a claim about detection.
Everything else in this repo follows the same rule — see `tracing-to-a-consumer` for the version
about outputs, and `verifying-a-reload` for the version about which copy your evidence describes.

## Related

`verifying-a-reload` — a green suite against a stale artefact is the same error one level up.
`tracing-to-a-consumer` — a test can pass because nothing requires the thing it checks.
