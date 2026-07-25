"""The Kb facade — every query the MCP server exposes."""

from __future__ import annotations

import difflib
import sqlite3
from dataclasses import dataclass

from owasp_kb.core.models import OutlineNode, RelatedEdge, RequirementRow, SearchHit
from owasp_kb.core.registry import Pack, get_pack, list_packs, pack_id
from owasp_kb.core.retrieval import build_retriever


@dataclass(frozen=True)
class KbInfo:
    packs: list[Pack]
    retrieval_mode: str


class Kb:
    """Read-only query surface over a built index."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._retriever = build_retriever(conn)

    # -- introspection ---------------------------------------------------

    def info(self) -> KbInfo:
        return KbInfo(packs=list_packs(self._conn), retrieval_mode=self._retriever.mode)

    def _pack_names(self) -> list[str]:
        return [p.name for p in list_packs(self._conn)]

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
        """
        hits = self._retriever.search(query, pack=pack, level=level, limit=limit)
        if not hits:
            searched = pack or ", ".join(self._pack_names())
            raise LookupError(
                f"no match for {query!r} in packs [{searched}]. This means the query found "
                "nothing, NOT that no security requirements apply. Try different wording."
            )
        return hits

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
        # Numeric-aware ordering so V10 sorts after V9. Lexical ordering would put
        # V10.1.1 before V2.1.1 and silently corrupt any gap report.
        sql += (
            " ORDER BY CAST(SUBSTR(chapter_id, 2) AS INTEGER),"
            " CAST(SUBSTR(section_id, INSTR(section_id, '.') + 1) AS INTEGER),"
            " CAST(SUBSTR(req_id, LENGTH(section_id) + 2) AS INTEGER)"
        )
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
