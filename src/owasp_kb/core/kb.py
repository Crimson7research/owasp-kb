"""The Kb facade — every query the MCP server exposes."""

from __future__ import annotations

import difflib
import sqlite3
from dataclasses import dataclass

from owasp_kb.core.models import (
    CatalogueEntry,
    OutlineNode,
    RelatedEdge,
    RequirementRow,
    SearchHit,
)
from owasp_kb.core.registry import Pack, get_pack, list_packs, pack_id
from owasp_kb.core.retrieval import build_retriever

# The three rels ingest/packs/cwe.py writes for the CWE graph. Named here rather
# than imported from that module because core must not depend on ingest -- the
# shipped server never loads it. The duplication is pinned by
# test_the_kb_catalogue_rels_match_what_the_ingest_writes: if the two lists drift,
# catalogue_related returns nothing at all rather than failing.
CATALOGUE_CHILD_REL = "cwe_child"
CATALOGUE_RELS = (CATALOGUE_CHILD_REL, "cwe_peer", "cwe_member")

# Measured on CWE 4.20 the deepest ancestor walk is 5 levels, so 20 is wide headroom
# rather than a real limit. It is not what makes the walk terminate -- the visited set
# is, and it does so even on the cycles the graph contains. The cap only bounds the
# work if a future release deepens the graph past 20.
#
# "5 levels" is BFS depth, which is what this constant bounds -- the loop below walks
# a frontier, so one iteration is one level regardless of how many nodes it holds.
# The longest simple ChildOf path is also 5, and the two metrics agreeing is luck, not
# a property: they measure different things and "chain length" names neither. Quote
# the metric, not the word. Mean BFS depth is 2.39 over the 969 Weaknesses (1.66 over
# all 1,391 entries, because a Category has no ChildOf parent at all).
#
# This said 13 for three releases of this file, a figure that reproduces under no
# methodology. Verified against the real catalogue through this exact code path, not a
# reimplementation of it: at a cap of 5 no entry truncates, at 4 nineteen do, at 3 a
# hundred and seven. tests/core/test_kb.py pins that with a realdata test, because the
# two synthetic boundary tests build their chains *from this constant* and so cannot
# fail when it shrinks.
#
# Where it does bite, it must say so, which is why CatalogueGraph carries a flag: a
# chain silently cut below its Pillar looks exactly like a chain that shares a Base
# or a Class, and that false "related" is the one answer this whole design exists to
# avoid. Truncation is the only failure mode here that corrupts the claim rather than
# merely losing data.
MAX_ANCESTOR_DEPTH = 20


@dataclass(frozen=True)
class LinkCoverage:
    """How much of the requirement set a relationship reaches.

    ``total_requirements`` is scoped to the pack(s) the relationship's edges
    actually anchor to, not to every requirement in the index. All four
    requirement-anchored relationships (guidance, cwe, nist, supersedes) are
    ASVS-keyed and ship no edge that could ever match a MASVS id, so with both
    packs loaded the honest denominator is ASVS's own size, not ASVS+MASVS --
    counting every pack would report a shortfall MASVS's presence could not
    possibly close, for every relationship, forever. This is the per-pack fix
    ``integrity.run_checks`` already applies to requirement counts, carried over
    to coverage: whichever pack(s) a relationship's from_id namespace resolves
    into is the population it could cover, and only that population is a
    meaningful denominator.

    ``requirements`` and ``total_requirements`` are None for a relationship that
    does not start at a requirement at all -- the CWE graph connects catalogue
    entries to each other, so "0 of 345 covered" is a denominator that does not
    apply, and rendering it reads as a mapping that failed to load.

    A requirement-scoped relationship that resolved nothing still reports 0.
    That is a real defect and must stay visible; the distinction here is
    structural, not "the count came out zero".
    """

    rel: str
    edges: int
    requirements: int | None
    total_requirements: int | None

    @property
    def share(self) -> float | None:
        if self.requirements is None or not self.total_requirements:
            return None
        return self.requirements / self.total_requirements


@dataclass(frozen=True)
class KbInfo:
    packs: list[Pack]
    retrieval_mode: str
    link_coverage: list[LinkCoverage]


@dataclass(frozen=True)
class CatalogueGraph:
    """Edges out of one catalogue entry, and whether the walk that found them stopped
    early.

    ``truncated`` is only ever True for an ancestor walk that hit
    MAX_ANCESTOR_DEPTH with ancestors still unexplored; a direct-edge query does no
    walking, so it reports False. Reported as a flag rather than raised, following
    the roster's ``complete``: raising would discard the ancestors already found and
    leave the caller with nothing, and a caller with nothing falls back on recalling
    a chain from memory, which is what this pack exists to replace.
    """

    edges: list[RelatedEdge]
    truncated: bool


class Kb:
    """Read-only query surface over a built index."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._retriever = build_retriever(conn)

    # -- introspection ---------------------------------------------------

    def info(self) -> KbInfo:
        return KbInfo(
            packs=list_packs(self._conn),
            retrieval_mode=self._retriever.mode,
            link_coverage=self._link_coverage(),
        )

    def _pack_names(self) -> list[str]:
        return [p.name for p in list_packs(self._conn)]

    def _link_coverage(self) -> list[LinkCoverage]:
        """Per-requirement coverage, counted the way related() resolves edges.

        A requirement reaches an edge through its own id, its section id, or its
        chapter id, so counting DISTINCT from_id would undercount guidance badly
        -- guidance is keyed on sections, giving 78 rather than the 332
        requirements that can actually reach it.

        A relationship with no edge anchored to any requirement identifier is not
        requirement-scoped, and reports None rather than 0. from_kind alone does
        not decide this: guidance is keyed on 'asvs_section' and is still
        reachable by 332 requirements, while the CWE graph is keyed on 'cwe' and
        is reachable by none.

        The denominator is the size of the pack(s) that own the requirements a
        relationship actually reached -- not every requirement in the index. A
        second checklist pack (MASVS) ships no links rows at all, so a rel like
        guidance can only ever match ASVS ids; counting MASVS's rows into the
        denominator would report a shortfall MASVS's presence could not possibly
        close. Requirements carry their pack in ``pack_id``, so the packs a
        relationship anchors to are read off the matched rows themselves rather
        than assumed to be "asvs" -- a rel that one day gains MASVS edges too
        would widen its own denominator with no code change here.
        """
        rels = [r[0] for r in self._conn.execute("SELECT DISTINCT rel FROM links")]
        coverage = []
        for rel in sorted(rels):
            edges = self._conn.execute(
                "SELECT COUNT(*) FROM links WHERE rel = ?", (rel,)
            ).fetchone()[0]
            # Requirements this rel actually reaches, grouped by the pack they
            # belong to. An empty result is exactly "not anchored to any
            # requirement" -- see the docstring above -- and is what
            # distinguishes the CWE graph (rel='cwe_child' etc, always empty
            # here) from a requirement-scoped rel that happens to resolve
            # nothing (which cannot happen today, but is not assumed away).
            matched = self._conn.execute(
                """
                SELECT r.pack_id AS pack_id, COUNT(*) AS n
                  FROM requirements r
                 WHERE EXISTS (
                   SELECT 1 FROM links x
                    WHERE x.rel = ?
                      AND x.from_id IN (r.req_id, r.section_id, r.chapter_id)
                 )
                 GROUP BY r.pack_id
                """,
                (rel,),
            ).fetchall()
            if not matched:
                coverage.append(
                    LinkCoverage(rel=rel, edges=edges, requirements=None, total_requirements=None)
                )
                continue
            reqs = sum(row["n"] for row in matched)
            anchored_pack_ids = [row["pack_id"] for row in matched]
            placeholders = ",".join("?" * len(anchored_pack_ids))
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM requirements WHERE pack_id IN ({placeholders})",
                anchored_pack_ids,
            ).fetchone()[0]
            coverage.append(
                LinkCoverage(rel=rel, edges=edges, requirements=reqs, total_requirements=total)
            )
        return coverage

    # -- search ----------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        pack: str | None = None,
        level: str | None = None,
        limit: int = 8,
    ) -> list[SearchHit]:
        """Search the index.

        Raises LookupError on no match rather than returning an empty list: an
        agent reads ``[]`` as "no requirements apply", which is a different and
        far more dangerous claim than "nothing matched".

        A ``level`` filter with no ``pack`` excludes level-less packs by
        construction -- asking for L2 is asking ASVS. Naming a level-less pack
        *and* a level is refused instead, because that call can only be a mistake.
        """
        if level is not None and pack is not None:
            self._reject_level_for_levelless_pack(pack)
        hits = self._retriever.search(query, pack=pack, level=level, limit=limit)
        if not hits:
            raise LookupError(self._no_match_message(query, pack=pack, level=level))
        return hits

    def _no_match_message(self, query: str, *, pack: str | None, level: str | None) -> str:
        """Name only the packs a failed search actually searched.

        A ``level`` filter with no ``pack`` structurally excludes every
        level-less pack -- SQL drops a NULL level -- so naming it among the
        "searched" packs licenses exactly the false inference the module
        docstring warns [] would: it reads as "MASVS has nothing on this",
        when MASVS was never queried at all. Naming a single ``pack`` has no
        such ambiguity, since that pack was rejected already if it has no
        levels and a level was asked for.
        """
        if pack is not None:
            searched = [pack]
            excluded: list[str] = []
        else:
            names = self._pack_names()
            excluded = [p for p in names if level is not None and not self._has_levels(p)]
            searched = [p for p in names if p not in excluded]
        note = ""
        if excluded:
            note = (
                f" level={level!r} excludes {', '.join(excluded)} (no levels defined), so "
                "despite being loaded it was NOT actually searched."
            )
        return (
            f"no match for {query!r} in packs [{', '.join(searched)}].{note} This means the "
            "query found nothing, NOT that no security requirements apply. Try different wording."
        )

    # -- corpus navigation -----------------------------------------------

    def _doc_id(self, doc_key: str) -> int:
        row = self._conn.execute("SELECT id FROM docs WHERE doc_key = ?", (doc_key,)).fetchone()
        if row is not None:
            return int(row["id"])
        all_keys = [r[0] for r in self._conn.execute("SELECT doc_key FROM docs")]
        close = difflib.get_close_matches(doc_key, all_keys, n=3)
        hint = f" Closest matches: {', '.join(close)}." if close else ""
        raise KeyError(f"unknown doc_key {doc_key!r}.{hint}")

    def outline(self, doc_key: str) -> list[OutlineNode]:
        """Heading tree for a document, so a caller can fetch one section."""
        doc_id = self._doc_id(doc_key)
        rows = self._conn.execute(
            "SELECT anchor, heading_path, depth, ord FROM sections WHERE doc_id = ? ORDER BY ord",
            (doc_id,),
        ).fetchall()
        return [
            OutlineNode(
                anchor=r["anchor"],
                heading=r["heading_path"].split(" > ")[-1],
                depth=r["depth"],
                ord=r["ord"],
            )
            for r in rows
        ]

    def get(self, doc_key: str, *, anchor: str | None = None) -> str:
        """Return a whole document, or one section when anchor is given."""
        doc_id = self._doc_id(doc_key)
        sql = (
            "SELECT c.text FROM chunks c JOIN sections s ON s.id = c.section_id WHERE s.doc_id = ?"
        )
        params: list[object] = [doc_id]
        if anchor is not None:
            sql += " AND s.anchor = ?"
            params.append(anchor)
        sql += " ORDER BY s.ord, c.id"
        rows = self._conn.execute(sql, params).fetchall()
        if not rows:
            if anchor is None:
                raise KeyError(f"document {doc_key!r} has no content")
            available = ", ".join(n.anchor for n in self.outline(doc_key))
            raise KeyError(
                f"unknown anchor {anchor!r} in {doc_key!r}. Available anchors: {available}"
            )
        return "\n\n".join(r["text"] for r in rows)

    # -- checklist packs -------------------------------------------------

    def _has_levels(self, pack: str) -> bool:
        """Whether any of this pack's requirements carry a level.

        Asked of the data, not of a list of pack names: a hardcoded list is a
        second place to update when a pack is added, and the one that gets missed.
        """
        row = self._conn.execute(
            "SELECT COUNT(*) FROM requirements r JOIN packs p ON p.id = r.pack_id"
            " WHERE p.name = ? AND r.level IS NOT NULL",
            (pack,),
        ).fetchone()
        return bool(row[0])

    def _reject_level_for_levelless_pack(self, pack: str) -> None:
        # Existence first: _has_levels' JOIN matches nothing for an unknown pack
        # name exactly as it does for a real, levelless one, so without this an
        # unknown pack was asserted to exist and merely lack levels -- get_pack
        # raises KeyError naming the available packs instead, matching how
        # Kb.checklist already handles this by calling get_pack first.
        get_pack(self._conn, pack)
        if self._has_levels(pack):
            return
        raise ValueError(
            f"pack {pack!r} defines no levels, so filtering by one would return an "
            "empty list, not a filtered one -- an agent reads [] as 'nothing in this "
            "pack meets that level', which is a different and far more dangerous "
            "claim than 'this pack has no levels'. Same reasoning Kb.search documents "
            "for raising LookupError instead of returning []. Omit level and level_exact."
        )

    def checklist(
        self,
        pack: str,
        *,
        chapter: str | None = None,
        section: str | None = None,
        req_id: str | None = None,
        level: str | None = None,
        level_exact: str | None = None,
    ) -> list[RequirementRow]:
        """Enumerate requirements from a checklist pack in deterministic order.

        ``level`` is CUMULATIVE, matching how ASVS defines its levels: level='2'
        returns the requirements an L2 assessment must verify, which is every L1
        and L2 requirement (253 in ASVS 5.0.0), not only those tagged L2 (183).
        Returning the tagged set would silently drop password minimums and every
        other L1 control from a report labelled L2.

        ``level_exact`` returns only the requirements tagged at that level, for
        the rarer case of inspecting one tier.
        """
        if level is not None and level_exact is not None:
            raise ValueError(
                "pass level or level_exact, not both: level is cumulative "
                "(L2 = L1 + L2), level_exact is a single tier"
            )
        meta = get_pack(self._conn, pack)
        if meta.type != "checklist":
            raise ValueError(
                f"pack {pack!r} is of type {meta.type!r}; owasp_checklist only applies to "
                "checklist packs. Use owasp_search or owasp_outline for corpus packs."
            )
        if level is not None or level_exact is not None:
            self._reject_level_for_levelless_pack(pack)
        sql = (
            "SELECT req_id, chapter_id, chapter_name, section_id, section_name, text, level"
            " FROM requirements WHERE pack_id = ?"
        )
        params: list[object] = [pack_id(self._conn, pack)]
        for column, value in (
            ("chapter_id", chapter),
            ("section_id", section),
            ("req_id", req_id),
        ):
            if value is not None:
                sql += f" AND {column} = ?"
                params.append(value)
        if level is not None:
            sql += " AND CAST(level AS INTEGER) <= ?"
            params.append(int(level))
        elif level_exact is not None:
            sql += " AND level = ?"
            params.append(level_exact)
        # Ordering is stored, not parsed. The expression this replaces read ASVS id
        # syntax -- SUBSTR(chapter_id, 2), the dot in section_id -- and evaluated to
        # 0 for every row of any pack whose ids are not shaped V<n>.<n>.<n>, which
        # left a second checklist pack ordered by whatever the table scan yielded.
        sql += " ORDER BY ord"
        rows = self._conn.execute(sql, params).fetchall()
        return [
            RequirementRow(
                req_id=r["req_id"],
                chapter_id=r["chapter_id"],
                chapter_name=r["chapter_name"],
                section_id=r["section_id"],
                section_name=r["section_name"],
                text=r["text"],
                level=r["level"],
            )
            for r in rows
        ]

    # -- graph traversal -------------------------------------------------

    def related(self, id: str, *, rel: str | None = None) -> list[RelatedEdge]:
        """Edges for a requirement id, section/chapter id, or doc_key.

        A requirement inherits its section's and chapter's guidance edges,
        because IndexASVS.md maps sections while agents ask about requirements.
        Without this roll-up the highest-value query in the system -- "which
        cheat sheet explains how to satisfy this requirement" -- returns nothing.
        """
        candidates = [id]
        parts = id.split(".")
        if len(parts) == 3:
            candidates.append(f"{parts[0]}.{parts[1]}")
        if len(parts) >= 2:
            candidates.append(parts[0])

        placeholders = ",".join("?" * len(candidates))
        sql = f"SELECT rel, to_kind, to_id, source FROM links WHERE from_id IN ({placeholders})"
        params: list[object] = list(candidates)
        if rel is not None:
            sql += " AND rel = ?"
            params.append(rel)
        sql += " ORDER BY rel, to_id"
        rows = self._conn.execute(sql, params).fetchall()
        return [
            RelatedEdge(rel=r["rel"], to_kind=r["to_kind"], to_id=r["to_id"], source=r["source"])
            for r in rows
        ]

    # -- catalogue packs -------------------------------------------------

    def catalogue_entry(self, entry_id: str) -> CatalogueEntry:
        """One catalogue entry by id, or KeyError naming it.

        An id is in the catalogue or it is not -- unlike an anchor, there is no
        useful list of alternatives to suggest.
        """
        row = self._conn.execute(
            "SELECT entry_id, kind, name, abstraction, status, description,"
            " extended_description FROM catalogue_entries WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        if row is None:
            raise KeyError(
                f"unknown catalogue id {entry_id!r}. Every Weakness and Category of the "
                "loaded catalogue is present, so an id that is missing is either a View "
                "(deliberately not ingested -- a View is a perspective on the catalogue, "
                "not a definition of a weakness) or not a real id at this catalogue "
                "version. Check the number before citing it."
            )
        return CatalogueEntry(
            entry_id=row["entry_id"],
            kind=row["kind"],
            name=row["name"],
            abstraction=row["abstraction"],
            status=row["status"],
            description=row["description"],
            extended_description=row["extended_description"],
        )

    def catalogue_related(self, entry_id: str, *, ancestors: bool = False) -> CatalogueGraph:
        """Direct edges, or the whole ChildOf ancestor chain.

        Every node carries its abstraction, because a shared Pillar is not
        evidence of anything -- 28% of weakness pairs share some ancestor and only
        4% share a non-Pillar one. Walking is breadth-first with a visited set:
        the graph has cycles through PeerOf, and 25 entries are Deprecated with
        parents that may be too.

        Methodology for those two figures, recorded because the pair they replace
        (35%/5%) reproduced under no variant anyone tried, and nothing here said
        what had been sampled: **random pairs drawn from the 969 Weaknesses of CWE
        4.20; ancestors computed transitively over cwe_child (ChildOf) only; a node
        is excluded from its own ancestor set; Pillar means abstraction == 'Pillar',
        of which there are 10.** 300k pairs gives 27.8% and 4.1%, a 6.8x asymmetry.
        Rounded to 28% and 4% deliberately -- a figure quoted to a tenth invites the
        belief that the methodology was pinned, and until this paragraph it was not.

        ``ancestors=True`` follows cwe_child only. The result is the set of
        ancestors, nearest first, not a tree: which child each edge was reached
        from is dropped, because the question a caller asks of a chain is how
        coarse its shared node is.

        Raises KeyError for an id that is not in the catalogue, exactly as
        catalogue_entry does. The id space here is closed and enumerable, so an
        unknown id is a mis-cited number and must not come back as an entry that
        happens to have no relationships. Kb.related is deliberately the opposite:
        for a requirement id, no edges is a real answer about the mapping.
        """
        # Called for its KeyError, nothing else: an id absent from the catalogue must
        # not come back as an entry that happens to have no relationships. Deleting
        # this line reverts the contract to whatever each caller does about it, which
        # is the drift consolidating it here ended. Pinned by
        # test_catalogue_related_on_an_unknown_id_raises_rather_than_returning_no_edges.
        self.catalogue_entry(entry_id)
        if ancestors:
            return self._catalogue_ancestors(entry_id)
        return CatalogueGraph(
            edges=self._catalogue_edges([entry_id], rels=CATALOGUE_RELS), truncated=False
        )

    def _catalogue_edges(self, from_ids: list[str], *, rels: tuple[str, ...]) -> list[RelatedEdge]:
        """Edges out of any of ``from_ids``, with each target's abstraction.

        The join to catalogue_entries is a LEFT JOIN, and that is the whole
        correctness of this method: CWE keeps edges pointing outside any subset of
        itself, so an inner join drops them silently. Measured on the test catalogue:
        all four of CWE-320's Has_Member targets are absent from it, and two of the
        five ids an ancestor walk from CWE-120 reaches are too (CWE-20 and CWE-787).
        An inner join answers "no members" for an Obsolete Category that eight ASVS
        requirements cite, which is the answer a caller is trying to get away from. A
        missing target yields abstraction=None instead.
        """
        if not from_ids:
            return []
        from_placeholders = ",".join("?" * len(from_ids))
        rel_placeholders = ",".join("?" * len(rels))
        rows = self._conn.execute(
            "SELECT l.rel AS rel, l.to_kind AS to_kind, l.to_id AS to_id,"
            " l.source AS source, e.abstraction AS abstraction"
            "  FROM links l"
            "  LEFT JOIN catalogue_entries e ON e.entry_id = l.to_id"
            f" WHERE l.from_id IN ({from_placeholders}) AND l.rel IN ({rel_placeholders})"
            " ORDER BY l.rel, l.to_id",
            (*from_ids, *rels),
        ).fetchall()
        return [
            RelatedEdge(
                rel=r["rel"],
                to_kind=r["to_kind"],
                to_id=r["to_id"],
                source=r["source"],
                abstraction=r["abstraction"],
            )
            for r in rows
        ]

    def _catalogue_ancestors(self, entry_id: str) -> CatalogueGraph:
        """Breadth-first over cwe_child, nearest ancestors first.

        Ancestors the cap stopped the walk from reaching are reported rather than
        swallowed: see MAX_ANCESTOR_DEPTH.
        """
        edges: list[RelatedEdge] = []
        visited = {entry_id}
        frontier = [entry_id]
        for _ in range(MAX_ANCESTOR_DEPTH):
            if not frontier:
                break
            parents = self._catalogue_edges(frontier, rels=(CATALOGUE_CHILD_REL,))
            frontier = []
            for edge in parents:
                if edge.to_id in visited:
                    continue
                visited.add(edge.to_id)
                edges.append(edge)
                frontier.append(edge.to_id)
        # bool(frontier) would over-report by one level: what it leaves are nodes
        # discovered but not expanded, and a chain of exactly MAX_ANCESTOR_DEPTH edges
        # ends there with nothing above it. Flagging that complete chain as truncated
        # tells a caller to discard a sound comparison -- this flag's own harm, in
        # reverse. So one more query, in a branch no published chain reaches, and the
        # flag means what both docstrings say it means. A frontier whose only parents
        # are already visited is a cycle closing, not an ancestor missed.
        unexpanded = self._catalogue_edges(frontier, rels=(CATALOGUE_CHILD_REL,))
        return CatalogueGraph(
            edges=edges,
            truncated=any(edge.to_id not in visited for edge in unexpanded),
        )
