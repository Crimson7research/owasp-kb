---
name: owasp-threat-model
description: Use when reviewing architecture or system design before implementation, threat modelling, evaluating a proposed design for security, assessing a new service or integration, triaging a reported vulnerability, or answering what could go wrong with a design - including SSRF, XSS, XXE, IDOR, CSRF, path traversal, directory traversal, open redirect, server-side template injection, privilege escalation, SQL injection, command injection, LDAP injection and deserialization. Pulls ASVS documentation-class requirements and cheat sheets relevant to each component.
  Use when reviewing architecture or system design before implementation,
  threat modelling, evaluating a proposed design for security, assessing a new
  service or integration, or answering what could go wrong with a design. Pulls
  ASVS documentation-class requirements and cheat sheets relevant to each
  component.
---

# Threat modelling with OWASP guidance

Review a design before code exists, grounded in ASVS requirements rather than intuition.

## Before starting: agree the scope

Ask these in **one message**, with defaults marked, so the user can reply "defaults except
scope: the new upload service". If they decline to answer or say to just get on with it,
proceed on the defaults — but **state every assumption in the output** so it is visible and
disputable rather than silent.

1. **Scope** — which component, service or integration is under review? What is
   explicitly out of scope?

2. **Deployment context** — where does this run and who can reach it? Internet-facing,
   internal-only, air-gapped? This is what turns "is this a real threat here" from a guess
   into a defensible call.

3. **Trust boundaries** — which interfaces accept data from outside the team's control?
   State the ones you can see; ask the user to confirm or add to the list.

4. **Design source** — is the design documented (a doc, diagram or spec), or must it be
   inferred from code? Inferring from code is weaker evidence and should be flagged as
   such in the output, not presented with the same confidence as a stated design.

5. **Eventual assessment level** — a threat model is not level-scoped the way a
   verification pass is, but ask which ASVS level the design will eventually be verified
   against (L1, L2, or L3 — cumulative: 70 / 253 / 345 requirements), since that shapes
   which gaps are worth flagging now versus later.

## Process

1. **Decompose the design** into components, trust boundaries and data flows. State what
   you understood, so a wrong reading gets corrected early.

2. **Pull the documentation requirements.** Each ASVS chapter opens with a documentation
   section (V1.1, V2.1, V5.1, V6.1, V7.1, V8.1 and so on) covering what the design must
   define. Call `owasp_checklist(pack='asvs', section='<Vx.1>')` for the chapters your
   components touch. **Do not answer from memory.**

3. **Per component, search for applicable guidance.** Call `owasp_search` with the component
   and its technology, then `owasp_outline(<doc_key>)` and `owasp_get(<doc_key>,
   anchor=...)` on what matches. A component handling uploads, one issuing tokens, and one
   rendering HTML have entirely different requirement sets.

4. **Cross to requirements.** For each relevant cheat sheet, call `owasp_related` to reach
   the ASVS requirements, so the model distinguishes advisory from required.

5. **Output**: per trust boundary, the threats, the ASVS requirements addressing them, and
   which are unaddressed by the current design. Cite everything.

## Rules

- Threats without a mapped requirement are still threats — record them and say they fall
  outside ASVS coverage rather than dropping them.
- Prefer stating an assumption over interrupting; collect open questions and present them
  at the end.

## If the knowledge base is unreachable

Say so explicitly and stop rather than producing a design review from memory.
