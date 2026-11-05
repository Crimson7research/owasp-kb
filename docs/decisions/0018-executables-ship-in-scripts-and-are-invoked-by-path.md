# 0018. Executables ship in scripts/ and are invoked by path

Date: 2026-09-08

## Status

Accepted. Adopts c7-marketplace ADR 0019, which reverses that repository's ADR 0008.

**It supersedes nothing here, and that absence is the finding.** `bin/` was never argued
in this repository. There is no ADR to reread, no premise to recheck, no rejected
alternative on record — the convention arrived because Claude Code appends
`<plugin_root>/bin` to `PATH` unconditionally, so it simply worked, and nothing was
written down that a later reader could disagree with. That is how this repository ended
up the fleet's last holdout: of every plugin cached on a developer's machine, exactly one
shipped `bin/`, and c7-marketplace ADR 0008's supporting evidence for the convention was
"`owasp-kb` already relies on this" — a citation of the one plugin that had never made the
argument. Retiring that citation is part of what this ADR records. An unargued convention
does not get revisited, because there is nothing to revisit.

## Context

The objection is not to what `bin/` contains. Claude Code appends `<plugin_root>/bin` to
`PATH` for every installed plugin, whether or not the directory exists, and nothing in
`plugin.json` declares it. So a hosted plugin's executables reach an agent's `PATH`
without ever appearing on the admin approval surface an org admin approves the plugin
from. Organization sync rejects such a plugin outright; it rejected a sibling for exactly
this (c7-marketplace issue #30). An empty `bin/` is still appended, which is why the
structural check added here does not look inside one.

`CLAUDE_PLUGIN_ROOT` is set for a hook process and not for a `Bash` tool call. That is the
load-bearing fact of this whole design, and it disposes of the obvious middle path.
ADR 0008 chose a bare name because the alternatives looked worse; there is in fact no
alternative that preserves a short bare name from inside a tool call, because nothing sets
the variable an agent would need to build one. Off `PATH`, `owasp-kb` is
command-not-found, and the process that can resolve the path is not the process that needs
it.

Nothing was broken at runtime before the move — the bare name resolved, every documented
command worked, and no doc in this repository claims a hosted or org install, so the
defect was latent rather than live. What the move did break is worth recording, because it
was invisible until the directory changed: `plugins/owasp-kb/hooks/flag_security_topic.py`
was inserting `bin/` onto `sys.path` to import `owasp_kb_cli.security_terms`, a coupling
between a hook and the CLI package that no manifest, no test name and no docstring
mentioned. Five tests in `tests/test_host_cli.py` fail when that path is wrong, so the
suite caught it — but only after the rename made it wrong. A directory whose location is
depended on from three unrelated places, with the dependency written out by hand in each,
is a convention nobody had to state and therefore nobody could check.

## Decision

Executables ship in the plugin's `scripts/`, off `PATH`. A `SessionStart` hook,
`state_host_cli.py`, states the absolute `scripts/` directory and names the commands —
`report merge`, `doctor`, `sessions` — unconditionally, in every session, in plain absolute
form with nothing left for the reader to compute. Docs and skills write
`python3 <scripts>/<tool>`, where `<scripts>` is the token that stands for the directory
that session's note named; a literal path carries a plugin-cache version segment the next
update invalidates, and a token resolved fresh each session does not. Every file using the
token defines it, in fixed wording, so an agent holding two of the fleet's plugins in
context sees one convention rather than two that rhyme. A library or hook naming a sibling
tool derives the path from `__file__` rather than repeating the convention by hand —
`invocation()` in `plugins/owasp-kb/scripts/owasp_kb_cli/doctor.py` is that rule applied to
the remedy strings, which are printed to a human who is already stuck and for whom a bare
name is a second dead end.

**A SEPARATE HOOK, NOT MORE PAYLOAD ON THE NUDGE.** The plugin now ships five hooks, two of
them `SessionStart`, and the second was not folded into the first. The two fail in opposite
directions. The nudge failing open to silence is correct — its own docstring argues that
direction, where ADR [0012](0012-enforcement-mechanisms.md) says it belongs, on the grounds
that failing closed would break session startup over a reminder and the degraded state is
just the behaviour the plugin had before the hook existed. This note falling silent is not
that. It is a command-not-found some minutes later, at the one step of an assessment that
cannot be worked around. Sharing a process would couple the two in both directions — an
exception in path resolution would suppress the nudge, and a malformed nudge would suppress
the path. ADR [0017](0017-a-session-start-hook-argues-the-token-ledger.md) also bounds the
nudge with "its only bound is that it is short", so appending a tools inventory to a payload
whose entire defence is brevity spends the only bound it has. `state_host_cli.py` fails open
too, for a reason of its own: the degraded state is a longer road to the path, not a broken
session.

**UNCONDITIONAL, ON ITS OWN REASONING.** Not inherited from the nudge, which is
unconditional for a different reason and records that as a known weakness. `doctor` and
`sessions` serve a machine with no assessment in flight — checking an install, listing what
is on disk — so gating the note on session state would leave them unreachable in exactly
the case where `doctor` is what someone needs.

**THREE CHECKS, EACH BLIND WHERE ANOTHER LOOKS.** In `tests/test_packaging.py`:

- `test_no_plugin_ships_a_bin_directory` refuses the directory itself from existing. It is
  what stops the pattern this ADR reverses from quietly reappearing.
- `test_every_scripts_token_names_a_real_tool_and_every_file_using_one_defines_it` refuses
  a `<scripts>/<name>` token that resolves to no tool, and a file that uses the token
  without expanding it. The second half is not pedantry: a skill is read piecewise — a gate
  branches to one continuation file or the other, never both — so a reader who arrives by
  one file's own read path holds a token no other file in the skill can expand for them.
- `test_no_doc_names_the_host_cli_as_a_bare_command` catches what the token check cannot
  see. That check fires on the token, so a line still reading ``run `owasp-kb doctor` ``
  carries no token, is seen by nothing, and passes while instructing an agent to type
  something that is not on `PATH`. c7-marketplace's own migration left four such sites
  behind precisely because nothing looked for them, so on this branch the check was written
  first and its output was used as the work queue: it enumerated nine sites across four
  files — `README.md`, `docs/install.md`, and both assessment skills.

The third check's narrowness is deliberate and is the reason it will survive. A bare name in
prose is legitimate and stays: "`owasp-kb doctor` reports this before it happens" is about
the tool, not an instruction to type it. Only a command-shaped mention is refused — first
token of a line inside a fenced block, a span carrying a flag, or a span that is the object
of an imperative run verb — and the last two are excused by an explainer appearing above
them, which makes the check satisfiable by moving the explainer earlier rather than by
weakening the sentence. A check that flagged the prose case would be worked around, or
deleted rather than obeyed, and would then be guarding nothing.

`docs/decisions/` is excluded from both document checks as historical record: ADR
[0014](0014-image-digest-pin.md) says `bin/owasp-kb-report` became `bin/owasp-kb`, which was
true when written and has to stay as written.

**THE DEPTH THAT DID NOT NEED CHANGING.** The driving issue asked for `plugin_root()` and the
entry point's `sys.path` insert to be corrected for the new location. Both were already
correct — `scripts/` sits at exactly the depth `bin/` did, so the move is a rename and the
arithmetic is unchanged. The criterion worth keeping was therefore not an edit but a test
that pins the depth, because the failure it guards is not a crash: a wrong answer is
`doctor` reporting on a different install than the one running, which is the single question
a stale install makes unanswerable.

## Consequences

- **Commands are longer and no longer survive in muscle memory.** `python3 <scripts>/owasp-kb
  report merge …` is not something a colleague types from memory the way a bare name was.

- **The path is not stable across a session boundary** the way a `PATH` entry was. It must be
  re-read from the session note each session rather than remembered, and a note that is
  remembered from the previous session may name a stale cache directory.

- **A subagent never receives the note.** `SessionStart` `additionalContext` reaches the main
  thread, and a subagent composes its own context. Both assessment skills fan out to
  subagents and both name `report merge`, so each documents the `Base directory for this
  skill:` fallback the `Skill` tool prints — two levels up, then into `scripts/`. Without it
  the convention is broken in exactly the processes this plugin routes the real work to. The
  bare name of the old convention did not suffer this, because it worked in any process; this
  is a capability the change gives up, not an oversight it introduces.

- **The known limitation: the non-Claude installs cannot expand the token.** (Codex now
  installs the plugin itself, so only the OpenCode part of this paragraph is current;
  see issue #94.) `install/codex.sh` and `install/opencode.sh` copied only `plugins/owasp-kb/skills/*/` — into `~/.codex/skills/`
  and `~/.config/opencode/skill/` respectively — and then print an MCP server snippet naming
  the pinned image. They ship no hooks, no `scripts/`, and no plugin manifest. There is no
  `SessionStart` hook in those harnesses and no `CLAUDE_PLUGIN_ROOT`, so a copied skill's
  `<scripts>` token expands to nothing at all. The per-skill fallback covers this partly and
  imperfectly, because it names the `Skill` tool's `Base directory for this skill:` line and
  those harnesses announce a loaded skill differently. Recorded as a limitation rather than
  fixed: solving it means a per-harness path story larger than this change, and the CLI is a
  host tool those installs do not ship in the first place — a Codex user has no
  `plugins/owasp-kb/scripts/owasp-kb` to invoke by any spelling.

- **The hook enforces nothing, and the checks are the only enforcement here.** ADR
  [0012](0012-enforcement-mechanisms.md) classes a `SessionStart` hook as a discovery
  mechanism rather than an enforcement one, and this one fits that exactly: it states a
  path, requires nothing downstream, and an agent can ignore it silently — the shape ADR
  [0010](0010-enforce-invariants-in-code.md) records as the repository's dominant defect.
  What holds the convention up is the three structural checks, and they act on the
  documents rather than on the session, because every failure mode here is silent in a
  different direction. A renamed tool leaves a documented command that runs nothing; a
  reflowed doc leaves a token nobody can expand; a reappearing `bin/` leaves a plugin that
  installs locally, passes the suite, and is rejected by org sync. None of the three is
  visible in a diff, and the last one is not visible on this machine at all.
