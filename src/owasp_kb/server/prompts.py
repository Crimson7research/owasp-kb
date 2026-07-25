"""MCP prompts. Clients such as Claude Code surface these as slash commands."""

from __future__ import annotations

from collections.abc import Callable

NO_MEMORY = (
    "Do not answer from memory. Every claim must come from a tool result and carry its "
    "citation. If the knowledge base is unreachable, say so explicitly instead of "
    "falling back on recalled guidance."
)


def build_prompts() -> list[Callable[..., str]]:
    """Return the prompt callables."""

    def asvs_chapter_review(chapter: str, level: str = "2") -> str:
        """Walk one ASVS chapter as a verification pass."""
        return (
            f"Perform an ASVS verification pass over chapter {chapter} at level {level}.\n\n"
            f"1. Call owasp_checklist(pack='asvs', chapter='{chapter}', level='{level}') to "
            "get every applicable requirement.\n"
            "2. For each requirement, call owasp_related(<req_id>) to find the cheat sheet "
            "that explains how to satisfy it, then read the relevant section with "
            "owasp_outline followed by owasp_get.\n"
            "3. Assess the current codebase against each requirement and record PASS, FAIL "
            "or N/A with a one-line justification and a file reference.\n"
            "4. Present a table of requirement id, level, verdict, evidence.\n\n"
            f"{NO_MEMORY}"
        )

    def cheatsheet(topic: str) -> str:
        """Look up OWASP Cheat Sheet guidance on a topic."""
        return (
            f"Find the authoritative OWASP guidance on: {topic}.\n\n"
            f"1. Call owasp_search('{topic}') to locate the relevant material.\n"
            "2. Call owasp_outline(<doc_key>) on the best-matching cheat sheet.\n"
            "3. Call owasp_get(<doc_key>, anchor=<anchor>) for the specific section rather "
            "than fetching the whole document; the largest exceeds 37,000 characters.\n"
            "4. Call owasp_related on any ASVS requirement ids returned, to see what is "
            "actually required as opposed to merely recommended.\n"
            "5. Summarise the guidance with citations, then state how it applies here.\n\n"
            f"{NO_MEMORY}"
        )

    def asvs_gap_report(scope: str, level: str = "2") -> str:
        """Produce an ASVS gap report for a scope at a target level."""
        return (
            f"Produce an ASVS level {level} gap report for: {scope}.\n\n"
            f"1. Call owasp_checklist(pack='asvs', level='{level}') for the full requirement "
            "set. Do not sample - a gap report must be complete. Work chapter by chapter "
            "with the chapter filter if the full response is unwieldy.\n"
            "2. Group requirements by chapter.\n"
            "3. For each, determine MET, GAP or NOT APPLICABLE for the scope, with evidence: "
            "a file and line, a configuration value, or a stated reason.\n"
            "4. For every GAP, call owasp_related(<req_id>) and cite the cheat sheet section "
            "describing the remediation.\n"
            "5. Output a summary count per chapter, then the full table with columns "
            "requirement id, level, status, evidence, remediation reference.\n"
            "6. Cite the exact ASVS version from kb_info so the report is reproducible.\n\n"
            f"{NO_MEMORY}"
        )

    return [asvs_chapter_review, cheatsheet, asvs_gap_report]
