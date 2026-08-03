# 9. Orchestration ships as agent definitions, not skill prose

## Status

Accepted, after a failed first delivery and one seriously-considered
alternative that was proposed in detail and then withdrawn.

## Context

The ASVS assessment runs as a fan-out: five roles, dispatched in a specific
shape, with specific things each role must not be able to do (see
[docs/architecture.md](../architecture.md#the-assessment-layer)). That shape had
to be expressed somewhere.

The obvious place is skill prose — describe the roles in `SKILL.md` and let the
main agent dispatch `general-purpose` subagents with the right instructions.
**This project's own history argues against it.** Tool descriptions here became
trigger lists because agents skipped descriptions that read as nouns. Skill
bodies had to *mandate* calls rather than mention them. And issue #8 established
that a direct instruction whose result nothing downstream consumed was skipped
100% of the time. "Dispatch 17 orchestrators, each spawning a finder per
requirement, each verified by an independent refuter" is a far more elaborate
instruction than the one that was already being ignored.

The four constraints the design actually needs are not stylistic:

1. no role may write to the codebase;
2. the refuter gets no knowledge-base access and never sees the requirement text
   it is challenging;
3. the finder cannot return N/A;
4. only the orchestrator can dispatch.

Under prompt prose, all four are requests. Under an agent definition's `tools:`
line, three of them are capabilities the role does not have.

## Decision

Ship the five roles as plugin agent definitions in
`plugins/owasp-kb/agents/*.md`, with **tool allowlists as the enforcement
mechanism**, and grant MCP access inside the allowlist via the server-level
wildcard:

```yaml
tools: ToolSearch, Task, Read, Grep, mcp__plugin_owasp-kb_owasp-kb__*
```

The tests for the four constraints were written *before* the definitions
(`tests/test_packaging.py`), so a role that quietly gains `Write`, or a refuter
that gains MCP, fails the build rather than the assessment.

**Rejected: superpowers-style prompt templates dispatched against
`general-purpose`.** This was not a strawman — it was proposed at length, with a
survey behind it (no plugin ships both an MCP server and agents; of 15 agents
across 6 plugins, only 4 declare `tools:` at all) and with a probe that had
accidentally demonstrated it working. It would have dissolved the MCP-access
problem entirely, because an unrestricted agent inherits the full tool surface.
It was withdrawn because of what it costs: **`owasp-exemption-refuter` must not
be able to reach the knowledge base.** Under a prompt template, its blindness
degrades from a missing capability to an instruction — which is precisely the
failure mode this design exists to prevent. It was the right answer only while
option 1 looked unsupported.

Two other options were rejected in the same round: dropping `tools:` from the
three MCP-dependent roles (same cost, less honestly), and passing requirement
text down through the prompt instead of granting MCP (it costs the property that
the finder reaches the knowledge base directly for every claim it makes — text
arriving through a prompt can be truncated or paraphrased upstream).

## Consequences

- **The allowlists silently filtered out the MCP tools the roles were instructed
  to load, and the first real run collapsed.** Three of five roles were
  effectively toolless for their actual job; the split was clean — *every
  MCP-free role worked, every MCP-dependent role failed*. The orchestrator's
  `ToolSearch` returned nothing and the fan-out degenerated into a central loop
  in the main session, which is the thing it existed to avoid. `ToolSearch`
  itself was missing from the surface the agent actually got, so the role could
  not even discover what it was missing.
- **The pre-flight probe that cleared this risk had tested the wrong artefact.**
  The risk was recorded as *"RESOLVED, verified"* on the strength of a dispatched
  subagent successfully calling `kb_info` — but that probe tested tool
  *inheritance*, not tool *permission*, because it dispatched an agent with no
  allowlist. The allowlists were the entire reason the question was open and the
  probe removed them. The lesson is narrower than "probe first", which was
  already the rule here and was followed: **probe the artefact you intend to
  ship, not a convenient stand-in for it.** The same standard was then applied
  to the fix — an initial close on documentation was reopened, and the issue
  stayed open until the plugin had been reinstalled at 0.4.0 and a real
  `owasp-chapter-orchestrator` had reached MCP through its allowlist in
  practice.
- **The tool id embeds the plugin name.** `mcp__plugin_owasp-kb_owasp-kb__*`
  resolves only for an install under the name `owasp-kb`. An install under a
  different name breaks the grant, silently, in exactly the way described above.
  This is a known limitation, recorded rather than solved.
- **Every skill change now needs a plugin version bump.** The plugin cache is
  version-keyed, so edits to an agent definition or a skill body do not reach an
  installed plugin without one — 0.3.0 → 0.4.0 → 0.5.0 → 0.6.0 across this
  work, each for that reason. One session spent ~9.5 hours talking to a stale
  server that reported a successful reconnect. This is now enforced rather than
  remembered: a content digest is recorded against the version and a test refuses
  when the two disagree, so a forgotten bump fails a test instead of shipping a
  plugin that cannot be updated. See
  [build.md](../build.md#the-plugin-version-is-the-delivery-mechanism).
- **The roles are Claude-Code-specific in a way the MCP server deliberately is
  not.** `agents/*.md` frontmatter (`tools:`, `model:`, `maxTurns:`) has no
  equivalent in the Codex/OpenCode install path, which copies skill directories
  only. Those clients get the knowledge base and the non-fan-out skills; they do
  not get the enforced fan-out.
- **What the allowlist cannot enforce still has to be prose**, and is marked as
  such: the completion sentinel and the verdict vocabulary live in the prompt
  bodies, and the invariants that could be moved into code were moved there —
  see ADR [0010](0010-enforce-invariants-in-code.md).
