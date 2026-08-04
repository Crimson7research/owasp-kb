# Discoverability

## The problem

An MCP server can be perfectly correct and still go unused. An agent decides
whether to call a tool from its name and description alone, before it has any
evidence the tool matters for the task in front of it. A description that
reads as a noun — "OWASP knowledge base search", "ASVS requirement lookup" —
describes what the tool *is* without ever asserting that *this specific
question* needs it. Observed behavior (not a hypothesis): an agent facing a
question about, say, session cookies will often just answer from training
data and never call a tool whose description never said "sessions" or
"cookies" anywhere. The tool schema costs context on every single turn whether
or not it gets called, so a server nobody calls is worse than useless — it is
pure overhead for zero benefit, and the failure is silent: nothing errors,
the agent just answers confidently from memory instead.

## The layered response

No single layer below is sufficient by itself; each catches what the others
miss, at a different point in an agent's decision process.

**1. Trigger-worded tool descriptions.** Every tool description in
`server/tools.py` is written as an explicit list of topics an agent might be
handling right now, not a summary of the tool's function. `owasp_search`'s
description leads with "Call this BEFORE answering anything involving:"
followed by the full `TOOL_TRIGGER_TOPICS` list:

```
authentication, passwords, MFA, sessions, cookies, JWT, OAuth, OIDC,
authorization, access control, input validation, SQL injection, command
injection, LDAP injection, XSS, output encoding, deserialization, file
upload, file download, cryptography, TLS, key management, secrets, logging,
error handling, CSRF, CORS, security headers, GraphQL, WebSocket, WebRTC,
API security, secure design review
```

This is a concrete word-match surface, not a vibe: an agent whose current
task mentions "cookies" or "CORS" sees that word verbatim in the tool
description it is scanning, at the moment it is deciding whether any tool
applies — the same mechanism a keyword search relies on, applied to the one
piece of text an agent actually reads before deciding to call a tool.

**2. Trigger-worded skill descriptions.** The same principle one level up: each
of the four skill frontmatter `description` fields is a list of triggering
situations (topics, task types — "writing or reviewing application code
touching authentication, passwords, MFA, sessions, cookies, tokens, JWT,
OAuth, OIDC...", "performing a security assessment, penetration test, code
audit..."), not a one-line summary of what the skill does. Claude Code
surfaces skill descriptions to the model as a discovery signal in exactly the
same "does this word match my task" way as tool descriptions, so the same
technique applies. `tests/test_packaging.py` enforces this is not accidental:
`test_skill_frontmatter_has_name_and_description` requires every description
exceed 120 characters specifically because a short description cannot hold
enough distinct trigger words to be a reliable discovery surface.

**3. Skill bodies that mandate the call and require citations.** Getting a
skill to trigger is necessary but not sufficient — a triggered skill that
still lets the model answer from memory has only moved the failure one layer
down. Every skill body states "Do not answer from memory" in those or
equivalent words, names the specific tool call to make first, and requires
every claim carry an inline citation (an ASVS id or a cheat sheet anchor).
`tests/test_packaging.py::test_skill_body_mandates_tool_use_and_forbids_memory`
enforces the phrase is present and that at least one real tool name
(`owasp_search` or `owasp_checklist`) is referenced by name in the body, not
just implied.

**4. MCP prompts shipped with the server.** `server/prompts.py` defines three
prompts — `asvs_chapter_review`, `cheatsheet`, `asvs_gap_report` — each a
fully scripted, numbered procedure that names the exact tool calls to make and
in what order. Because these ship as MCP prompts rather than
client-specific files, Claude Code surfaces them as slash commands
automatically (no separate packaging step), and any other MCP-capable client
gets the identical prompt text through the same protocol mechanism. A prompt
is the strongest layer of the four — invoking it *is* invoking the workflow —
but it only helps once a user or agent has already decided to reach for it,
which is exactly the discovery problem the first three layers exist to solve
before a prompt is even in play.

## What was rejected, and why

- **Standalone slash-command files.** Claude Code supports hand-authored
  `.md` command files under a `commands/` directory. Rejected because it would
  duplicate the three MCP prompts under a second, client-specific mechanism
  for no gain: MCP prompts already surface as slash commands in Claude Code
  natively, and a hand-authored duplicate would need to be kept in sync with
  the prompt definitions in `server/prompts.py` by hand, with no test able to
  catch drift between the two the way
  `tests/test_packaging.py::test_skills_only_reference_real_tools` catches
  skill/tool drift.

- **Claude Code hooks.** Hooks can react to Claude Code lifecycle events (a
  tool call, a session start) and could plausibly nudge the model toward
  calling `owasp_search`. Rejected because the discoverability problem is
  explicitly cross-agent — Claude Code is one of three target agents
  (alongside Codex and OpenCode), and a hook is a Claude-Code-only mechanism.
  Solving discoverability for one-third of the target surface while leaving
  Codex and OpenCode with a weaker mechanism was judged worse than a uniform
  solution (trigger-worded descriptions and skill bodies) that is identically
  effective everywhere the four layers above are honored by the client.

  **The plugin has since gained two hooks, and this rejection still stands.**
  They do not solve discoverability; they enforce assessment invariants that
  no tool description could — refusing a read of an excluded prior assessment,
  and refusing triage over an incomplete inventory. The cross-agent objection
  does not apply to them, because the fan-out they guard is already
  Claude-Code-only: it depends on `agents/*.md` frontmatter that has no
  equivalent in the Codex or OpenCode install path. A Claude-Code-only
  mechanism guarding a Claude-Code-only workflow costs the other clients
  nothing, whereas a Claude-Code-only *discovery* mechanism would have left
  two thirds of the target surface weaker. See ADR
  [0012](decisions/0012-enforcement-mechanisms.md).

## The anti-goal

The failure this entire design exists to prevent is **silent fallback to
recalled guidance**: an agent that does not call any tool, answers from
training data, and presents the answer with the same confidence and the same
surface plausibility as a properly cited one. There is no way to distinguish
the two from the output alone — that is exactly what makes it dangerous. Every
layer above is aimed at reducing how often that happens; none of them can make
it impossible, since an agent can always simply not call a tool. What the
skills can guarantee is that *when* the fallback happens, it is visible: every
skill body's "If the knowledge base is unreachable" section requires saying so
explicitly rather than silently proceeding on memory, so a genuinely
unreachable server produces a stated limitation instead of a confident,
uncited answer indistinguishable from a properly grounded one.
`tests/test_packaging.py::test_skill_body_handles_an_unreachable_server`
enforces every one of the four skill bodies contains the word "unreachable",
so this cannot regress silently either.

### The anti-goal, observed

It happened, and not through unreachability. A session triaging an SSRF defect
produced a repair plan without calling any tool here. The server was reachable and
the skill was installed and listed. Asked afterwards how it chose, the agent's
account was that the corpus "would add process overhead without new insight here".

Two likelier explanations were checked first and both were wrong, which is worth
recording because each implied a different fix. The command driving the session
maps work types to process skills and has no security branch — but the skill was
considered *outside* that table, so the enumeration did not exclude it. And
`owasp-secure-coding` said "when writing or reviewing application code" while the
session was planning — but that was not the reason given.

The actual cause was a **cost/benefit judgement made before looking**, and it was
checkably wrong: the plan covered domains, paths and ports and never mentioned
protocols, the first dimension ASVS V1.3.6 enumerates, and proposed
resolve-then-connect validation the SSRF cheat sheet documents as bypassable.

Two things follow, and the second matters more.

**A trigger list is only as good as its coverage of the corpus.** `SSRF` was absent
from both skill descriptions and from `TOOL_TRIGGER_TOPICS`, as were XXE, IDOR,
path traversal, open redirect, server-side template injection and privilege
escalation — while the corpus covered every one. Nothing compared the two, so the
gap was invisible. `test_every_flagged_vulnerability_is_served_by_the_corpus` now
compares the firing vocabulary against the built index, and
`test_every_flagged_vulnerability_is_advertised_by_the_tools` compares it against
the tool descriptions.

**But a trigger list cannot make an agent call anything.** It only makes the tool
findable, and findability was never the problem in this case. That is why the
routing mechanism added here is a `UserPromptSubmit` hook rather than a longer
description: a hook fires without being chosen, and the skill was chosen against.
Its payload argues about cost rather than value, because the objection was about
cost — checking is one call now; not checking risks a fix that ships, is believed
done, and is reopened later. See ADR 0012 for which failure each mechanism can
stop, and ADR 0014's sibling reasoning about proxies versus the thing itself.
