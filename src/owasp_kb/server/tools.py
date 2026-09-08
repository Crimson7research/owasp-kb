"""MCP tool adapters over Kb.

Descriptions are written as trigger lists rather than summaries: an agent decides
whether to call a tool from its description, and a description that reads like a
noun gets skipped. That is an observed failure mode, not a hypothetical one.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from typing import Any

from owasp_kb import __version__
from owasp_kb.core.kb import Kb
from owasp_kb.core.roster import (
    Finding,
    RosterError,
    build_roster,
    load_session_findings,
)

MAX_EXCERPT_CHARS = 1200
MAX_GET_CHARS = 30_000
LARGE_CHECKLIST_ROWS = 100

# The ceiling a tool result must stay under to be delivered at all. Enforced
# here rather than only asserted in the tests, which measured fixture-scale
# responses and so never saw the real enumeration exceed it: measured against
# ASVS 5.0.0, level='1' is 22,780 characters, level='2' is 76,845 and the full
# 345 are 103,134. A caller hit the transport limit on level='2' and could not
# read the response at all -- including the note inside it advising the
# chapter-at-a-time call that would have worked.
MAX_RESPONSE_CHARS = 40_000


def _normalised(text: str) -> str:
    """Whitespace-insensitive form, for comparing a quote to indexed text.

    Kb.get joins a section's chunks with a blank line, and chunking splits at 512
    tokens, so a quote spanning a chunk boundary contains whitespace the source
    document does not. Comparing raw text would reject correct quotes.
    """
    return " ".join(text.split())


# Relationships whose upstream mappings predate ASVS 5.0.0 and therefore cover
# only part of the requirement set. An empty owasp_related result for one of
# these must not be read as "no such mapping exists".
PARTIAL_COVERAGE_RELS = ("cwe", "nist", "supersedes")

# The pack ingest/packs/cwe.py registers. Named here rather than imported because
# the server never loads ingest; pinned against it by
# test_the_searched_pack_name_matches_what_the_ingest_writes, because a typo would
# turn cwe_search into an error about an unknown pack.
CWE_PACK = "cwe"

TOOL_TRIGGER_TOPICS = (
    "authentication",
    "passwords",
    "MFA",
    "sessions",
    "cookies",
    "JWT",
    "OAuth",
    "OIDC",
    "authorization",
    "access control",
    "input validation",
    "SQL injection",
    "command injection",
    "LDAP injection",
    # Added after a triage session skipped the corpus on an SSRF defect. Every one
    # of these was absent from every discovery surface while the corpus covered
    # them -- SSRF has its own cheat sheet and ASVS V1.3.6. The hook's firing
    # vocabulary is checked against this tuple by
    # test_every_flagged_vulnerability_is_advertised_by_the_tools.
    "SSRF",
    "XXE",
    "IDOR",
    "path traversal",
    "directory traversal",
    "open redirect",
    "server-side template injection",
    "privilege escalation",
    "XSS",
    "output encoding",
    "deserialization",
    "file upload",
    "file download",
    "cryptography",
    "TLS",
    "key management",
    "secrets",
    "logging",
    "error handling",
    "CSRF",
    "CORS",
    "security headers",
    "GraphQL",
    "WebSocket",
    "WebRTC",
    "API security",
    "secure design review",
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

    KeyError.__str__ is repr(args[0]), which wraps the message in quotes -- and in
    double quotes whenever the message itself contains a single one, which every
    message raised here does, because they all embed a value with !r. A
    ``.strip("'")`` therefore stripped nothing at any of the six raise sites, and
    every KeyError this module reported has shipped double-quote-wrapped. So read
    the argument rather than trying to strip whichever quoting repr chose.

    Pinned by test_no_error_message_is_quote_wrapped.
    """
    message = exc.args[0] if isinstance(exc, KeyError) and len(exc.args) == 1 else str(exc)
    return {"error": str(message)}


def _grouped(rows) -> list[dict]:
    """Group by chapter then section so names are stated once rather than per row.

    Measured 27% smaller on the full 345-requirement enumeration with no row
    dropped -- completeness is the point of this tool, so the saving comes from
    removing repetition, never from omitting content. Kb.checklist already
    returns rows in chapter -> section -> requirement order, so no pre-sort.
    """
    chapters = []
    for chapter_id, chapter_rows in itertools.groupby(rows, key=lambda r: r.chapter_id):
        chapter_rows = list(chapter_rows)
        sections = []
        for section_id, section_rows in itertools.groupby(chapter_rows, key=lambda r: r.section_id):
            section_rows = list(section_rows)
            sections.append(
                {
                    "id": section_id,
                    "name": section_rows[0].section_name,
                    # "L" is omitted rather than null for a pack without levels:
                    # a null in a tool response is a value an agent has to
                    # interpret, and there is nothing here to interpret.
                    "requirements": [
                        {"id": r.req_id, "text": r.text}
                        | ({"L": r.level} if r.level is not None else {})
                        for r in section_rows
                    ],
                }
            )
        chapters.append(
            {
                "id": chapter_id,
                "name": chapter_rows[0].chapter_name,
                "sections": sections,
            }
        )
    return chapters


def build_tools(kb: Kb) -> list[Callable[..., Any]]:
    """Return every tool callable bound to this Kb.

    The cwe_ tools are not owasp_-prefixed: CWE is MITRE's, and that prefix exists
    because the other tools serve OWASP material.
    """

    def _resolve_citation(finding: dict) -> str | None:
        """The section text a finding's remediation cites, or None if it cites nothing.

        A citation that points nowhere reads exactly like one that points somewhere,
        which is how a fabricated reference reaches a security report. Kb.get already
        raises KeyError naming the available anchors, so the message it produces is
        better than one written here.
        """
        remediation = finding.get("remediation")
        if not remediation:
            return None
        doc_key, _, anchor = remediation.partition("#")
        return kb.get(doc_key, anchor=anchor or None)

    def kb_info() -> dict:
        """Report which OWASP knowledge base packs are loaded, their versions, and
        the active retrieval mode. Call this first if you are unsure what content
        is available, or when you need exact version strings for citations.

        Also reports per-relationship link coverage: cwe and nist are
        partial because the upstream mappings predate ASVS 5.0.0, so a missing
        edge is not evidence that none exists.

        Coverage is reported only for relationships that start at a requirement.
        cwe_child, cwe_peer and cwe_member connect catalogue entries to each
        other, so they carry an edge count and no coverage -- absent because it
        does not apply, not because it is zero.

        server_version is the release this image was built from. Compare it
        against the release you expect to be running: a reconnect reports success
        whether or not the image behind it is current. It is not the plugin's
        version -- the plugin declares none, and the two drift on purpose. Two
        images can also report the same version and hold different indexes, so
        only the digest the plugin pins distinguishes those."""
        info = kb.info()
        return {
            "server_version": __version__,
            "retrieval_mode": info.retrieval_mode,
            "packs": [
                {
                    "name": p.name,
                    "type": p.type,
                    "version": p.version,
                    "commit_sha": p.commit_sha,
                    "license": p.license,
                }
                for p in info.packs
            ],
            # The coverage keys are omitted, not nulled, for a relationship no
            # requirement can reach: the CWE graph connects catalogue entries to
            # each other, and "0 of 345 covered" reads as a mapping that failed
            # to load. An absent field cannot be misread; a zero will be.
            "link_coverage": [
                {"rel": c.rel, "edges": c.edges}
                | (
                    {
                        "requirements_covered": c.requirements,
                        "total_requirements": c.total_requirements,
                    }
                    if c.requirements is not None
                    else {}
                )
                for c in info.link_coverage
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
                    "citation": h.citation,
                    "pack": h.pack,
                    "req_id": h.req_id,
                    "doc_key": h.doc_key,
                    "anchor": h.anchor,
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
        level_exact: str | None = None,
    ) -> dict:
        """Enumerate verification requirements from a checklist pack such as ASVS,
        filtered by chapter (V6), section (V6.2), requirement id (V6.2.1) or level.

        level is CUMULATIVE, as ASVS defines it: level='2' returns the 253
        requirements an L2 assessment must verify, including all 70 L1 ones.
        level='1' returns 70, level='3' returns all 345. Use level_exact only to
        inspect a single tier (level_exact='2' returns the 183 tagged L2).

        Use this for assessments, gap analysis and compliance reports where you
        need every applicable requirement rather than the best-matching few.

        Returns requirements grouped by chapter and section. Walk
        chapters[].sections[].requirements[]; the top-level count is the total
        and nothing is ever truncated."""
        try:
            rows = kb.checklist(
                pack,
                chapter=chapter,
                section=section,
                req_id=req_id,
                level=level,
                level_exact=level_exact,
            )
            version = next(p.version for p in kb.info().packs if p.name == pack)
        except (KeyError, ValueError) as exc:
            return _error(exc)
        chapters = _grouped(rows)
        response = {
            "pack": pack,
            "pack_version": version,
            "count": len(rows),
            "chapters": chapters,
        }
        # No truncation: a gap report needs every requirement, and silently
        # dropping rows from a compliance enumeration is worse than a large
        # response.
        if len(rows) > LARGE_CHECKLIST_ROWS:
            chapter_ids = [c["id"] for c in chapters]
            response["note"] = (
                f"{len(rows)} requirements returned in full; nothing is truncated. This is "
                "a large response. For a gap report, call once per chapter "
                f"({', '.join(chapter_ids)}) and keep a running tally -- the totals must "
                f"sum to {len(rows)}."
            )
        # Refuse rather than truncate, and refuse in a form the caller can act
        # on. The chapter argument already works and the largest single chapter
        # at level='2' is 9,808 characters, so the per-chapter path is not a
        # degraded fallback -- it is the call that should have been made. The
        # counts come back with it so the caller can reconcile its tally against
        # the total without a second enumeration.
        if len(json.dumps(response)) > MAX_RESPONSE_CHARS:
            return {
                "error": (
                    f"{len(rows)} requirements exceed the response limit. Nothing is "
                    "truncated and nothing is lost: call once per chapter with "
                    f"chapter='V1' and so on, and the totals must sum to {len(rows)}."
                ),
                "pack": pack,
                "pack_version": version,
                "count": len(rows),
                "chapters": [
                    {
                        "id": c["id"],
                        "name": c["name"],
                        "requirements": sum(len(s["requirements"]) for s in c["sections"]),
                    }
                    for c in chapters
                ],
            }
        return response

    def owasp_related(id: str, rel: str | None = None) -> dict:
        """Find content related to an ASVS requirement id (V6.2.1), an ASVS
        section or chapter id (V6.2, V6), or a cheat sheet doc_key.
        Relationships: 'guidance' (which cheat sheet explains how to satisfy a
        requirement), 'cwe', 'nist', 'supersedes'. Use this to go from "what is
        required" to "how do I do it"."""
        edges = kb.related(id, rel=rel)
        response = {
            "id": id,
            "edges": [
                {"rel": e.rel, "to_kind": e.to_kind, "to_id": e.to_id, "source": e.source}
                for e in edges
            ],
        }
        if not edges:
            # An empty list must not read as "no CWE applies". Upstream mappings
            # predate ASVS 5.0.0, so absence is frequently our gap rather than a
            # statement about the requirement.
            coverage = {c.rel: c for c in kb.info().link_coverage}
            gaps = [
                f"{r} covers {coverage[r].requirements}/{coverage[r].total_requirements} "
                f"requirements ({coverage[r].share:.0%})"
                for r in (PARTIAL_COVERAGE_RELS if rel is None else [rel])
                if r in coverage and coverage[r].share < 1.0
            ]
            if gaps:
                response["note"] = (
                    f"No edges found for {id}. Coverage is partial because the upstream "
                    f"mappings predate ASVS 5.0.0: {'; '.join(gaps)}. Absence of an edge "
                    "is NOT evidence that no such mapping exists for this requirement."
                )
        return response

    def cwe_get(entry_id: str) -> dict:
        """Look up one CWE weakness or category by id -- its name, abstraction,
        status and description.

        Call this before citing a CWE id that OWASP's ASVS mapping does not
        carry, which is the common case: of 95 ids cited in one real assessment,
        42 were not from the mapping. An id that is not in the catalogue is an
        error, not an empty result.

        status matters. CWE-320 'Key Management Errors' is Obsolete and eight
        ASVS requirements map to it, so substituting a live, specific weakness
        there is an improvement you can now evidence rather than assert.

        abstraction is the weakness's level -- Pillar, Class, Base, Variant or
        Compound -- and is null for a category, which has no level. It is stated
        rather than omitted so a comparison of two cited ids can see that one of
        them has nothing to compare.
        """
        try:
            entry = kb.catalogue_entry(entry_id)
        except KeyError as exc:
            return _error(exc)
        # Not truncated: measured on CWE 4.20 the longest description is 1,231
        # characters and the longest extended description 3,677, so the whole entry
        # is smaller than one cheat-sheet section.
        #
        # 1,231 is CWE-361, a Category: a Category has no Description element, so its
        # Summary is what lands in this column, and Summaries run longer than
        # Descriptions. The longest Weakness description is 505 -- which is the figure
        # this comment used to give for the whole catalogue, understating by 2.4x by
        # measuring only half of what cwe_get can return.
        return {
            "entry_id": entry.entry_id,
            "kind": entry.kind,
            "name": entry.name,
            "abstraction": entry.abstraction,
            "status": entry.status,
            "description": entry.description,
            "extended_description": entry.extended_description,
        }

    def cwe_search(query: str, limit: int = 8) -> dict:
        """Search the CWE catalogue by describing a weakness in your own words.

        Use this when you know what the defect is but not which CWE names it --
        for instance when OWASP's mapping is silent for a requirement, which it
        is for 141 of 345. Returns citable ids; a miss comes back as an empty hit
        list WITH a message saying the query found nothing, because 'no results'
        on its own reads as 'no such weakness exists'.

        entry_id on each hit is what you cite, and cwe_get on it gives the
        abstraction and status the citation needs.

        Hits are lexically ranked and near-ties are common: two entries can score
        identically and order arbitrarily between them. Read the top few and choose
        on the names and descriptions, not on rank.

        Args:
            query: Natural-language description of the defect.
            limit: Maximum hits to return.
        """
        try:
            hits = kb.search(query, pack=CWE_PACK, limit=limit)
        except (KeyError, ValueError) as exc:
            # KeyError before LookupError, as in owasp_search: an index built
            # without the CWE pack is a fact about this build, and reporting it as
            # "no match" would read as "no such weakness exists".
            return _error(exc)
        except LookupError as exc:
            return {"hits": [], "message": str(exc)}
        return {
            "hits": [
                {
                    # doc_key is the entry id: the ingest keys one document per
                    # catalogue entry on it.
                    "entry_id": h.doc_key,
                    "citation": h.citation,
                    "heading_path": h.heading_path,
                    "excerpt": _truncate(h.text, MAX_EXCERPT_CHARS),
                }
                for h in hits
            ]
        }

    def cwe_related(entry_id: str, ancestors: bool = False) -> dict:
        """Relationships for a CWE id: parents, peers, or a category's members.

        Call this before claiming that one CWE id refines, substitutes for, or is
        unrelated to another -- for instance when you are citing an id the ASVS
        mapping does not carry and need to say how it relates to the one it does.
        Pass ancestors=True on both ids and compare the chains.

        ancestors=True returns the whole ChildOf chain rather than direct parents,
        each node carrying its abstraction. On every edge, abstraction is the
        target's (to_id) and not the id you asked about, and it is null where the
        target is outside this catalogue.

        Deciding whether a cited id refines a mapped one or substitutes for it is
        your judgement, not this tool's: comparing two chains, a shared Pillar
        means almost nothing (28% of weakness pairs share some ancestor, only 4%
        share a non-Pillar one) while a shared Base or Class is meaningful. Say
        which you found and why in the report.

        cwe_peer is a catch-all, not PeerOf, and reading it as similarity is a
        mistake. It carries every non-ChildOf Related_Weakness nature: of 284 edges,
        CanPrecede 143, PeerOf 98, CanAlsoBe 27, Requires 13, StartsWith 3. The
        plurality is CanPrecede, a *sequence* relation, and it is stored in one
        direction only -- so a cwe_peer edge does not imply the reverse edge exists,
        and "these two are peers" is not what most of them say. Treat it as "these
        are related somehow, go read both entries" and do not infer symmetry.

        An id absent from the catalogue is an error, as it is for cwe_get: an
        empty edge list must mean "this entry records no relationships" and never
        "no such id", or a mis-cited number passes silently.

        truncated says whether the walk stopped before running out of ancestors.
        It is false for every chain in the published catalogue, and if it is ever
        true the chain you have is missing its coarsest end -- which is exactly
        where the Pillar sits, so do not read a shared Class off a truncated chain.
        """
        try:
            graph = kb.catalogue_related(entry_id, ancestors=ancestors)
        except KeyError as exc:
            return _error(exc)
        return {
            "entry_id": entry_id,
            "ancestors": ancestors,
            "truncated": graph.truncated,
            "edges": [
                {
                    "rel": e.rel,
                    "to_kind": e.to_kind,
                    "to_id": e.to_id,
                    "abstraction": e.abstraction,
                    "source": e.source,
                }
                for e in graph.edges
            ],
        }

    def owasp_roster(
        pack: str = "asvs",
        chapter_states: dict | None = None,
        findings: list | None = None,
        excluded: list | None = None,
        level: str | None = None,
        require_verification: bool = True,
        detail: bool = False,
        session: str | None = None,
    ) -> dict:
        """Assemble assessment verdicts into a complete, checked roster.

        Call this at the end of an assessment instead of tallying by hand. Every
        requirement is placed in exactly one verdict; any requirement you did not
        report a finding for becomes INSUFFICIENT EVIDENCE rather than being
        omitted, and the response states whether the roster is complete.

        chapter_states maps each chapter id to 'APPLIES' or an N/A verdict.
        findings is a list of dicts with req_id, chapter, section, verdict,
        evidence, and optionally file, line, cwe, remediation, remediation_quote,
        trace. Findings sharing a (file, line, cwe, verdict) are merged, keeping every
        requirement they cover.

        remediation cites guidance as 'doc_key#anchor', or 'doc_key' for the
        requirement-level mapping from owasp_related(rel='guidance'). It must
        resolve against the index or the finding is rejected -- an anchor that
        points nowhere reads exactly like one that points somewhere, which is how
        a fabricated reference reaches a report.

        remediation_quote is a verbatim fragment of the cited section, and asserts
        that you navigated to it and read it. It is checked against the section
        text, whitespace-normalised, so line breaks do not matter but paraphrase
        is rejected. Omit it when the citation is the requirement-level mapping
        rather than a section you read: an anchor alone proves the section exists,
        not that anyone read it.

        A claim asserting a checked outcome is rejected without its adversary's
        trace: a GAP and an 'INSUFFICIENT EVIDENCE (gap refuted)' need
        owasp-finding-verifier, an 'N/A (verified)' needs owasp-exemption-refuter.
        Record it as 'GAP (unconfirmed)', 'N/A (unverified)' or plain
        'INSUFFICIENT EVIDENCE' instead if it was not checked. Pass
        require_verification=False only for a deliberately quick pass.

        'INSUFFICIENT EVIDENCE (gap refuted)' is for a gap a verifier disproved.
        Refuting a reported defect does not establish the control is adequate, so
        it is not MET -- and it is not the plain verdict either, which means a
        finder could not tell or nobody looked.

        excluded lists prior assessment reports found in the target. Any finding
        citing one is rejected -- another assessment's conclusion is not evidence.
        Acknowledge such reports exist and do not open them.

        Returns counts, per-chapter totals, the entries needing attention
        (INSUFFICIENT EVIDENCE, INSUFFICIENT EVIDENCE (gap refuted),
        N/A (unverified), GAP (unconfirmed)) and each finding's id, verdict,
        location and covered requirements. It does not echo back the evidence you
        supplied. Pass detail=True for the full per-requirement entry list.

        Each finding also carries cwe_corpus: the CWE ids OWASP's mapping holds
        for the requirements it covers, or [] where the mapping is silent. Report
        it beside your own cwe rather than in place of it. The mapping is per
        requirement and a finding is per defect, so a more specific id is often
        right -- but a reader must be able to tell which came from where.
        """
        try:
            requirements = [
                {
                    "req_id": r.req_id,
                    "chapter": r.chapter_id,
                    "section": r.section_id,
                    "level": r.level,
                }
                for r in kb.checklist(pack, level=level)
            ]
            # Findings may arrive inline or from the session state file. The file
            # is what keeps a correction to one appended line instead of
            # re-sending every finding; inline still works unchanged, which is
            # what every existing caller and test uses.
            supplied = list(findings or [])
            if session is not None:
                supplied = load_session_findings(session) + supplied
            parsed = [
                Finding(
                    req_id=f["req_id"],
                    chapter=f["chapter"],
                    section=f["section"],
                    verdict=f["verdict"],
                    evidence=f.get("evidence", ""),
                    file=f.get("file"),
                    line=f.get("line"),
                    cwe=f.get("cwe"),
                    remediation=f.get("remediation"),
                    remediation_quote=f.get("remediation_quote"),
                    trace=f.get("trace"),
                )
                for f in supplied
            ]
            for finding in supplied:
                quote = finding.get("remediation_quote")
                if quote and not finding.get("remediation"):
                    raise RosterError(
                        f"{finding.get('req_id')} supplies a remediation_quote with no "
                        "remediation to check it against. Cite the section you read, or "
                        "drop the quote."
                    )
                try:
                    section = _resolve_citation(finding)
                except KeyError as exc:
                    raise RosterError(
                        f"{finding.get('req_id')} cites {finding.get('remediation')!r}, "
                        f"which does not resolve: {exc}"
                    ) from exc
                if quote and _normalised(quote) not in _normalised(section or ""):
                    raise RosterError(
                        f"{finding.get('req_id')} claims a quote from "
                        f"{finding.get('remediation')} that is not in that section. "
                        "Quote the text you read, or omit remediation_quote and the "
                        "citation is recorded as the requirement-level mapping rather "
                        "than a section you read."
                    )
            roster = build_roster(
                requirements=requirements,
                findings=parsed,
                chapter_states=chapter_states or {},
                excluded=excluded,
                require_verification=require_verification,
                detail=detail,
            )
            for entry in roster["findings"]:
                mapped: set[str] = set()
                for req_id in entry["covers"]:
                    mapped.update(edge.to_id for edge in kb.related(req_id, rel="cwe"))
                entry["cwe_corpus"] = sorted(mapped)
            return roster
        except (KeyError, ValueError, RosterError) as exc:
            return _error(exc)

    return [
        kb_info,
        owasp_search,
        owasp_outline,
        owasp_get,
        owasp_checklist,
        owasp_related,
        owasp_roster,
        cwe_get,
        cwe_related,
        cwe_search,
    ]
