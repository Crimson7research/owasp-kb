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

## Process

1. **Confirm scope and target level** before starting. A gap report against the wrong scope
   is wasted work.

2. **Pull the complete requirement set.** Call `owasp_checklist(pack='asvs', level=<level>)`.
   Completeness is the point — do not sample or summarise. **Do not answer from memory.**
   The unfiltered response is around 140,000 characters, so work chapter at a time with the
   `chapter` filter and keep a running tally.

3. **Classify every requirement** as `MET`, `GAP`, or `NOT APPLICABLE`, each with evidence:
   a file and line reference, a configuration value, or an explicit reason.

4. **For every GAP**, call `owasp_related(<req_id>)` and cite the cheat sheet section
   describing the remediation, so the report is actionable rather than a list of failures.

5. **Output**:
   - A summary count per ASVS chapter: met / gap / not applicable.
   - The full table: requirement id, level, status, evidence, remediation reference.
   - The exact ASVS version and pack versions from `kb_info`.

## Rules

- Report the total requirement count and confirm your table has that many rows. A silently
  truncated gap report reads as full coverage. Levels are cumulative: at L2 that is 253
  requirements (every L1 requirement plus every L2 one), not the 183 tagged L2.
- Do not soften a `GAP` into a partial pass. Partial compliance is a gap with a note.
- State that level counts come from the pinned ASVS release, so a future release may shift
  them.

## If the knowledge base is unreachable

Say so explicitly and stop. Do not produce a report from recalled requirements — a
compliance artefact with unverifiable ids is a liability.
