"""MCP tool adapters over Kb.

Descriptions are written as trigger lists rather than summaries: an agent decides
whether to call a tool from its description, and a description that reads like a
noun gets skipped. That is an observed failure mode, not a hypothetical one.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from owasp_kb.core.kb import Kb

MAX_EXCERPT_CHARS = 1200
MAX_GET_CHARS = 30_000

TOOL_TRIGGER_TOPICS = (
    "authentication", "passwords", "MFA", "sessions", "cookies", "JWT", "OAuth", "OIDC",
    "authorization", "access control", "input validation", "SQL injection",
    "command injection", "LDAP injection", "XSS", "output encoding", "deserialization",
    "file upload", "file download", "cryptography", "TLS", "key management", "secrets",
    "logging", "error handling", "CSRF", "CORS", "security headers", "GraphQL",
    "WebSocket", "WebRTC", "API security", "secure design review",
)

_TOPICS = ", ".join(TOOL_TRIGGER_TOPICS)

SEARCH_DESCRIPTION = (
    "Search authoritative OWASP security guidance (ASVS requirements and Cheat "
    f"Sheets). Call this BEFORE answering anything involving: {_TOPICS}. "
    "Do not answer from memory - return citable requirement IDs.\n\n"
    "Args:\n"
    "    query: Natural-language description of the security topic.\n"
    "    pack: Restrict to one pack, e.g. 'asvs' or 'cheatsheets'.\n"
    "    level: ASVS level '1', '2' or '3'. Applies to requirements only.\n"
    "    limit: Maximum hits to return."
)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f"\n[truncated at {limit} characters]"


def _error(exc: Exception) -> dict:
    """Core raises with actionable messages; surface them as plain strings.

    KeyError stringifies with surrounding quotes, which reads badly to an agent.
    """
    return {"error": str(exc).strip("'")}


def build_tools(kb: Kb) -> list[Callable[..., Any]]:
    """Return the six tool callables bound to this Kb."""

    def kb_info() -> dict:
        """Report which OWASP knowledge base packs are loaded, their versions, and
        the active retrieval mode. Call this first if you are unsure what content
        is available, or when you need exact version strings for citations."""
        info = kb.info()
        return {
            "retrieval_mode": info.retrieval_mode,
            "packs": [
                {
                    "name": p.name, "type": p.type, "version": p.version,
                    "commit_sha": p.commit_sha, "license": p.license,
                }
                for p in info.packs
            ],
        }

    def owasp_search(
        query: str,
        pack: str | None = None,
        level: str | None = None,
        limit: int = 8,
    ) -> dict:
        try:
            hits = kb.search(query, pack=pack, level=level, limit=limit)
        except (KeyError, ValueError) as exc:
            # KeyError is a LookupError subclass, so it must be caught first:
            # an unknown pack is an error, not "no match".
            return _error(exc)
        except LookupError as exc:
            # Deliberately not an empty list: an agent reads [] as "no
            # requirements apply", which is a different and dangerous claim.
            return {"hits": [], "message": str(exc)}
        return {
            "hits": [
                {
                    "citation": h.citation, "pack": h.pack, "req_id": h.req_id,
                    "doc_key": h.doc_key, "anchor": h.anchor,
                    "heading_path": h.heading_path,
                    "excerpt": _truncate(h.text, MAX_EXCERPT_CHARS),
                }
                for h in hits
            ]
        }

    owasp_search.__doc__ = SEARCH_DESCRIPTION

    def owasp_outline(doc_key: str) -> dict:
        """List the heading structure of one OWASP document with its section
        anchors. Call this before owasp_get on a large cheat sheet so you can
        fetch a single relevant section instead of the whole document - the
        largest is over 37,000 characters."""
        try:
            nodes = kb.outline(doc_key)
        except KeyError as exc:
            return _error(exc)
        return {
            "doc_key": doc_key,
            "sections": [
                {"anchor": n.anchor, "heading": n.heading, "depth": n.depth} for n in nodes
            ],
        }

    def owasp_get(doc_key: str, anchor: str | None = None) -> dict:
        """Fetch the full text of an OWASP document, or one section when anchor is
        given. Prefer passing an anchor from owasp_outline - whole cheat sheets
        can exceed 30,000 characters and will be truncated."""
        try:
            text = kb.get(doc_key, anchor=anchor)
        except KeyError as exc:
            return _error(exc)
        citation = f"{doc_key}#{anchor}" if anchor else doc_key
        return {"citation": citation, "text": _truncate(text, MAX_GET_CHARS)}

    def owasp_checklist(
        pack: str = "asvs",
        chapter: str | None = None,
        section: str | None = None,
        req_id: str | None = None,
        level: str | None = None,
    ) -> dict:
        """Enumerate verification requirements from a checklist pack such as ASVS,
        filtered by chapter (V6), section (V6.2), requirement id (V6.2.1) or level
        (1/2/3). Use this for assessments, gap analysis and compliance reports
        where you need every applicable requirement rather than the best-matching
        few."""
        try:
            rows = kb.checklist(
                pack, chapter=chapter, section=section, req_id=req_id, level=level
            )
            version = next(p.version for p in kb.info().packs if p.name == pack)
        except (KeyError, ValueError) as exc:
            return _error(exc)
        return {
            "pack": pack,
            "pack_version": version,
            "count": len(rows),
            "requirements": [
                {
                    "req_id": r.req_id, "level": r.level, "chapter": r.chapter_id,
                    "chapter_name": r.chapter_name, "section": r.section_id,
                    "section_name": r.section_name, "text": r.text,
                }
                for r in rows
            ],
        }

    def owasp_related(id: str, rel: str | None = None) -> dict:
        """Find content related to an ASVS requirement id (V6.2.1), an ASVS
        section or chapter id (V6.2, V6), or a cheat sheet doc_key.
        Relationships: 'guidance' (which cheat sheet explains how to satisfy a
        requirement), 'cwe', 'nist', 'supersedes'. Use this to go from "what is
        required" to "how do I do it"."""
        edges = kb.related(id, rel=rel)
        return {
            "id": id,
            "edges": [
                {"rel": e.rel, "to_kind": e.to_kind, "to_id": e.to_id, "source": e.source}
                for e in edges
            ],
        }

    return [kb_info, owasp_search, owasp_outline, owasp_get, owasp_checklist, owasp_related]
