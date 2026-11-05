"""The reviewed chapter-level map from AI cheat sheets to AISVS chapters.

Upstream links only three chapters to a cheat sheet: C2 and C10 in their own
References lists, and C8 from the RAG Security cheat sheet. Without this map,
AI_Agent_Security, Secure_AI_Model_Ops and Secure_Coding_with_AI link to no
requirement at all, so the discovery path -- search, land on a cheat sheet,
follow the edge to the requirement -- stops at the cheat sheet.

Each entry names the cheat sheet sections that justify it, checked against
the pinned Cheat Sheet Series commit and AISVS 1.01. A chapter is listed only
where the cheat sheet gives that chapter's subject a section of its own; a
passing mention does not count. The AISVS research wiki carries finer links,
but it is AI-generated and mutable upstream, so it is not used (see
docs/kb-packs.md).

Edges from this map carry the source ``CURATED_SOURCE``, so a reader of
owasp_related can tell them from the upstream ones. Where upstream already
states an edge, upstream wins: its edge is inserted first and the links
primary key ignores the duplicate.
"""

from __future__ import annotations

CURATED_SOURCE = "owasp-kb curated AISVS map"

CURATED_GUIDANCE: dict[str, tuple[str, ...]] = {
    # 2 Input Validation & Prompt Injection Defense -> C2; 5 Output Validation &
    # Guardrails -> C7; 3 Memory & Context Security -> C8; 1 Tool Security &
    # Least Privilege, 4 Human-in-the-Loop Controls, 7 Multi-Agent Security ->
    # C9; 9 Secure Agent Testing & Adversarial Validation -> C11;
    # 6 Monitoring & Observability -> C12.
    "AI_Agent_Security_Cheat_Sheet": ("C2", "C7", "C8", "C9", "C11", "C12"),
    # 1 Model Development & Training -> C1, C3; 3 Model Storage & Artifacts ->
    # C3, C6; 5 Deployment & Infrastructure, 6 Runtime & Hardware Isolation ->
    # C4; 8 Adversarial Robustness -> C11; 7 Monitoring & Logging -> C12.
    "Secure_AI_Model_Ops_Cheat_Sheet": ("C1", "C3", "C4", "C6", "C11", "C12"),
    # Section 5 Agent Runtime Sandboxing, 11 CI/CD Agents and Confused Deputy
    # Risk, 13 Multi-Agent and Sub-Agent Propagation -> C9; Section 4 MCP and
    # Tool Security -> C10. Its dependency sections concern generated code,
    # not model supply chain, so C6 is deliberately absent.
    "Secure_Coding_with_AI_Cheat_Sheet": ("C9", "C10"),
    # The whole sheet is about the integrity and completeness of agent
    # execution records -> C12 Monitoring, Logging & Anomaly Detection.
    "Verifying_Third_Party_Agent_Execution_Evidence_Cheat_Sheet": ("C12",),
}
