---
name: owasp-threat-model
description: >
  Use when reviewing architecture or system design before implementation,
  threat modelling, evaluating a proposed design for security, assessing a new
  service or integration, or answering what could go wrong with a design. Pulls
  ASVS documentation-class requirements and cheat sheets relevant to each
  component.
---

# Threat modelling with OWASP guidance

Review a design before code exists, grounded in ASVS requirements rather than intuition.

## Process

1. **Decompose the design** into components, trust boundaries and data flows. State what
   you understood, so a wrong reading gets corrected early.

2. **Pull the documentation requirements.** Each ASVS chapter opens with a documentation
   section (V1.1, V2.1, V5.1, V6.1, V7.1, V8.1 and so on) covering what the design must
   define. Call `owasp_checklist(pack='asvs', section='<Vx.1>')` for the chapters your
   components touch. **Do not answer from memory.**

3. **Per component, search for applicable guidance.** Call `owasp_search` with the component
   and its technology, then `owasp_outline` and `owasp_get` on what matches. A component
   handling uploads, one issuing tokens, and one rendering HTML have entirely different
   requirement sets.

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
