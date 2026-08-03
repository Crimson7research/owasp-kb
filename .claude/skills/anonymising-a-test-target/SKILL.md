---
name: anonymising-a-test-target
description: Strip the identity of a real codebase out of anything that gets written down, while keeping the measurement it produced. Use this whenever a run, scan, test or assessment against a real project is about to be cited — in a commit message, issue, PR body, doc, plan, spec, agent prompt or test fixture — and whenever quoting a finding, a file path, a source excerpt or a session log from one. The target is the instrument, not the subject: write "a scan on a project", never the project's name.
---

# Anonymising a test target

Real codebases are how this tool gets measured. Their identity is not the evidence and it is not
ours to publish. Everything written down — commits, issues, PR bodies, docs, plans, specs, agent
prompts, fixtures — describes **a project**, never a named one.

This is the write-time half of a control that already exists. `docs/publishing.md` and
`scripts/preflight_publish.sh` are the publish-time half: a gitignored `.publish-scrub` list of
identifiers, grepped over every tracked surface. Two things sit outside its reach:

- it greps tracked files, so it **never sees the issue tracker** — and no history rewrite touches
  that either, because the tracker is not in git
- plans and specs under `docs/superpowers/` are gitignored, so nothing checks them at all

Those are where prose about a run naturally accumulates. Not writing the identity down is the only
control that reaches them.

## The name buys nothing

Two ways to cite the same run:

| | |
|---|---|
| ✅ | "a complete single-agent run — ESP32 firmware, 253 requirements at L2, 544-line report, 62 FAILs" |
| ❌ | "a real single-agent assessment (ESP32 firmware, `<name>`)" |

The first is fully reproducible reasoning that names nobody. The second spends a name on top of the
same category and buys no information with it. Anything a reader does with the citation — judge the
scale, compare a later run, decide whether a design holds — works from the figures alone.

## The vocabulary

| Instead of | Write |
|---|---|
| "Run against `<name>`" | "a run on a project", "a scan on a project" |
| "the `<name>` L2 report" | "the project's L2 report", "the report from that run" |
| a real checkout path | "the target repo" — keep the real path in local notes, never in the tree |
| "an ESP32 firmware, `<name>`" | "an ESP32 firmware codebase" |
| a target source path with line range | "a source path with a line range, mid-list" — the shape is the evidence |

## Keep the measurement, drop the identity

Anonymising must not cost you the finding. These are different axes, and conflating them is how the
leak gets justified. `docs/publishing.md` puts it as: the measurements are the valuable content, and
they are safe.

| Keep — this is the evidence | Drop — this is identity |
|---|---|
| category: firmware, web API, mobile client | project, repo, org or client name |
| scale: source-file count, requirement count, report length | absolute paths, home directories, usernames |
| run parameters: level, scope, exclusions | target source paths, class and symbol names |
| outcomes: FAIL counts, finding counts, verdict distribution | quoted target source, hostnames, endpoints, IPs |
| our own session ids, SHAs, dates, agent counts | anything naming the file a defect lived in |
| the *shape* of a defect | the file it was in |

A reasoning chain that leans on a real path cannot be fixed by find-and-replace — the argument
around it depends on the specifics. Rewrite it against a neutral example, or drop it.

Absolute paths fail twice over: they identify a machine *and* they are useless to a colleague who
checks the repo out somewhere else. Write the path relative to the repo root, or describe the role
of the file.

## The check

For tracked files, `scripts/preflight_publish.sh` already does it. For the body of an issue, PR or
commit message — which no script can see — write it to a file first and scan that:

```bash
scrub=$(grep -vE '^[[:space:]]*(#|$)' .publish-scrub)
[ -n "$scrub" ] || { echo "empty scrub list: this check would pass anything" >&2; exit 2; }
printf '%s\n' "$scrub" | grep -nIFf - "$BODY"            # named identifiers
grep -nIE '/(home|Users)/[^/]+/' "$BODY"                 # any absolute home path, any user
grep -nIF -e "$HOME" -e "$(id -un)" "$BODY"              # this machine's own layout
```

The path patterns are derived, not pinned: `$HOME` and `id -un` describe whoever runs the check, and
`/(home|Users)/[^/]+/` catches any colleague's layout on Linux or macOS. A checklist listing one
person's directories only ever protects that person.

The guard on an empty list is not decoration. With no patterns, `grep -F -f` matches **every line**,
and folding the list into one alternation regex matches every line silently — both read as
"checked". Verified by mutation: with the list emptied, the check reported all three lines of a
three-line file, one of which was clean.

**When you first run against a new target**, add its identifiers to `.publish-scrub` — repo name,
distinctive symbols, output paths, hostnames. The list is only as good as the memory of whoever
writes it, so it gets written the day the target is first used, not at publication.

**Do not build that list from recall.** Enumerate targets from what is written, because recall
misses whole engagements — a sweep over every revision here surfaced a second target that a
memory-built list had left out entirely:

```bash
mapfile -t revs < <(git rev-list --all)      # bash: zsh does not split $revs
git grep -ahIoE '(the|a|an|second|first) [A-Za-z0-9_-]{2,20} (assessment|report|run|target)' \
  "${revs[@]}" -- | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | head -30
```

Concrete descriptors stand out against generic ones like "a gap report" or "a real target".

**Then classify every match before scrubbing it.** A blanket path pattern is worse than no pattern:
`/home/[a-z]+` over this repository matches a devcontainer's `ENV PATH=/home/dev/…`, an
already-anonymous `/home/you` placeholder, and a `/home/solutions` path inside an upstream CWE
reference URL. One of the four was a leak. Scrubbing the other three corrupts a fixture, breaks the
devcontainer, and changes `plugins/` content — which the digest guard rejects, correctly.

Editing an issue afterwards does not retract it from notifications, mail or anyone's cache. Check
before the send.

## Rationalisations

| Excuse | Reality |
|---|---|
| "The repo is private" | Private is a setting, not a property of the text. `docs/publishing.md` exists because going public is the plan, and `.claude/` is one of the surfaces it scans. |
| "The name is needed to reproduce" | Reproduction needs path, level, scope and exclusions. Keep the path in local notes; nothing in a tracker reproduces anything. |
| "It's my own project, not a client's" | The habit is what protects the client run. A convention applied selectively is one you forget under time pressure. |
| "Anonymising loses the evidence" | The figures carry the argument. The name has never been load-bearing in one. |
| "It's only a file path" | A path can carry the project name in a directory component, and a symbol name in the filename. |
| "It's in `docs/superpowers/`, which gets discarded" | Discarded on a *history rewrite* that may never happen, and only for files. Readable by everyone with the repo until then. |
| "I'll clean it up before publishing" | Find-and-replace cannot repair reasoning built on specifics, and the tracker is not in scope for any scrub script. |

## Red flags

Pasting a session log excerpt. Quoting a finding verbatim. Copying an agent's `file:line` output
into an issue. Writing a plan step that says "re-run against …". Building a fixture from a real
run's output. Illustrating a rule in an agent prompt with a real symbol.

**Every one of these carries identity in by default.** The usual leak is not a name someone decided
to write — it arrives inside a file path, pasted as evidence for an unrelated bug. Check before the
write, not after.

## Related

`docs/publishing.md` — the publish-time scrub, its surfaces, and what is safe to keep.
`tracing-to-a-consumer` — ask what actually requires the name. Nothing usually does.
`mutation-checking-a-test` — the same discipline for fixtures: build them from shapes, not from a
real run's output.
