---
name: owasp-asvs-verify
description: >
  Use when performing a security assessment, penetration test, code audit,
  security review, or verification of an application against the OWASP
  Application Security Verification Standard. Walks ASVS requirements by
  chapter and level, records pass/fail/not-applicable per requirement id with
  evidence, and maps findings to ASVS ids and CWE identifiers.
---

# ASVS verification pass

Drive a structured assessment against ASVS, producing per-requirement verdicts with evidence.

## Process

1. **Establish the target level.** Ask if unstated. L1 is opportunistic, L2 is the standard
   for most applications, L3 is for high-value systems. ASVS 5.0.0 has 345 requirements:
   70 at L1, 183 at L2, 92 at L3.

2. **Enumerate, do not sample.** Call `owasp_checklist(pack='asvs', chapter=..., level=...)`.
   An assessment that examines the best-matching few requirements is not an assessment.
   **Do not answer from memory** — requirement text and ids must come from the tool. Work
   chapter by chapter; the unfiltered response is large.

3. **Work requirement by requirement.** For each:
   - Call `owasp_related(<req_id>)` for the cheat sheet explaining compliance, and its CWE.
   - Read the relevant section with `owasp_outline` then `owasp_get`.
   - Inspect the actual code or configuration.
   - Record `PASS`, `FAIL` or `N/A` with a file and line reference, or a stated reason.

4. **Output a table**: requirement id, level, verdict, evidence, CWE.

5. **Cite the exact ASVS version** from `kb_info` so the assessment can be reproduced.

## Rules

- `N/A` requires a justification. An unjustified `N/A` is an undocumented `FAIL`.
- Never mark `PASS` on a plausible-looking implementation without reading it.
- CWE coverage is partial — 204 of 345 requirements — because upstream publishes only a
  bleeding-edge mapping. Absence of a CWE is not evidence of anything.

## If the knowledge base is unreachable

Say so explicitly and stop. An assessment with invented requirement ids is worse than no
assessment, because it looks authoritative.
