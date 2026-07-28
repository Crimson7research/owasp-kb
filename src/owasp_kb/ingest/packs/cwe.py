"""Ingest the MITRE CWE catalogue into catalogue_entries, its graph, and chunks.

Not an OWASP project. Present because ASVS maps to it, and because a finding that
cites CWE-789 is unverifiable unless the catalogue is queryable by id.

Views are not ingested. None of them is mapped, and a View is a perspective on the
catalogue rather than a definition of a weakness, so it has no citable text.

Categories are ingested alongside Weaknesses because four ASVS-mapped ids are
Categories. Deprecated and Obsolete entries are kept for the same reason: CWE-320
is Obsolete and eight ASVS requirements cite it, so dropping it would make the
enforcement reject a legitimate citation.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

from owasp_kb.core.chunking import chunk_markdown
from owasp_kb.core.registry import Pack, pack_id, upsert_pack

PACK_NAME = "cwe"
SOURCE_URL = "https://cwe.mitre.org"

# Only these rels are produced here, so clearing by rel scopes the delete to this
# ingest without depending on the source filename, which carries the version.
CWE_RELS = ("cwe_child", "cwe_peer", "cwe_member")

_DESCRIPTION_ANCHOR = "description"


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _flatten(el: ET.Element | None) -> str:
    """Flatten within each block, keeping the blank line between blocks.

    ``el.text`` is not enough: ``Extended_Description`` wraps its prose in nested
    ``xhtml:p`` children, so reading only the direct text returns the indentation
    before the first child and drops the description entirely.

    Collapsing the whole element to a single line is also wrong. ``_split_oversized``
    in ``core/chunking`` splits only on blank lines and otherwise returns the body as
    one part, so a single-line flatten of a long entry becomes one oversized chunk
    that the embedder truncates at 512 tokens. Measured on 4.20: 12 extended
    descriptions exceed the threshold as one line, and preserving paragraphs takes
    that to 8.

    It does not reach 0, because ``_split_oversized`` never size-checks its *final*
    block: ``chunk_markdown`` strips the body, so the last paragraph has no trailing
    blank line to close it and is appended unconditionally. Whether an entry is
    rescued therefore depends on where its largest paragraph sits. CWE-1240
    (``[97, 131, 330, 150, 61, 146]``) splits into three chunks because its largest
    is mid-document; CWE-1251 (``[32, 109, 153, 64, 35, 482]``) stays in one
    880-token chunk because its largest is last. Tracked as #38 -- the fix belongs
    in core/chunking, which is shared with the other two packs.

    Child tails are not collected, which is safe rather than lucky: no child of any
    Description, Extended_Description or Summary in 4.20 carries a non-whitespace
    tail, so this loses no content anywhere in the catalogue.
    """
    if el is None:
        return ""
    blocks = [" ".join("".join(child.itertext()).split()) for child in el]
    if el.text and el.text.strip():
        blocks.insert(0, " ".join(el.text.split()))
    return "\n\n".join(block for block in blocks if block)


def _entry_id(raw: str | None) -> str | None:
    """Normalise a bare catalogue number to the cited form.

    The XML carries bare numbers in ``ID`` and ``CWE_ID``; every id reaching the
    database gets the ``CWE-`` prefix, for entries and for both ends of every link,
    or the joins that resolve a citation to an entry match nothing.
    """
    if raw is None:
        return None
    return f"CWE-{raw}"


def _clear_pack(conn: sqlite3.Connection, pid: int) -> None:
    """Remove this pack's rows so a rebuild cannot duplicate or leave stale content.

    catalogue_entries references chunks via a foreign key, so it must go first.
    Chunks are deleted through the chunks table, never chunks_fts, so the
    external-content sync triggers remove the matching postings.

    Clearing ``links`` has no precedent in the other packs -- asvs.py does not touch
    the table -- but without it an edge that upstream withdrew would survive a
    rebuild, because the inserts are OR IGNORE and nothing else prunes. It is scoped
    by ``rel`` rather than by ``source``, which carries the catalogue version and so
    would strand the previous release's rows on a bump. An exact IN list is used
    deliberately: ``links.py`` stores the ASVS->CWE mapping as ``rel='cwe'``, which
    a prefix match like ``rel LIKE 'cwe%'`` would wipe along with ours.
    """
    conn.execute("DELETE FROM catalogue_entries WHERE pack_id = ?", (pid,))
    conn.execute(
        "DELETE FROM chunks WHERE section_id IN"
        " (SELECT s.id FROM sections s JOIN docs d ON d.id = s.doc_id WHERE d.pack_id = ?)",
        (pid,),
    )
    conn.execute(
        "DELETE FROM sections WHERE doc_id IN (SELECT id FROM docs WHERE pack_id = ?)", (pid,)
    )
    conn.execute("DELETE FROM docs WHERE pack_id = ?", (pid,))
    placeholders = ", ".join("?" * len(CWE_RELS))
    conn.execute(f"DELETE FROM links WHERE rel IN ({placeholders})", CWE_RELS)


def _as_markdown(title: str, description: str, extended: str) -> str:
    """Build the document the chunker splits, one H2 per non-empty field."""
    parts = [f"# {title}", "", "## Description", "", description]
    if extended:
        parts += ["", "## Extended Description", "", extended]
    return "\n".join(parts)


def _insert_entry_document(
    conn: sqlite3.Connection,
    pid: int,
    *,
    entry_id: str,
    name: str,
    description: str,
    extended: str,
) -> int | None:
    """Write the docs, sections and chunks rows. Returns the description chunk id.

    The description of a weakness is at most 505 characters in 4.20, well under the
    chunker's threshold, so it yields a single chunk. Should a future release make
    one long enough to split, the first part wins: it opens the definition, so it is
    the piece that identifies the weakness rather than elaborating on it.
    """
    number = entry_id.removeprefix("CWE-")
    title = f"{entry_id}: {name}"
    cur = conn.execute(
        "INSERT INTO docs (pack_id, doc_key, title, source_url) VALUES (?, ?, ?, ?)",
        (pid, entry_id, title, f"{SOURCE_URL}/data/definitions/{number}.html"),
    )
    doc_id = int(cur.lastrowid)

    section_ids: dict[str, int] = {}
    description_chunk_id: int | None = None
    for chunk in chunk_markdown(_as_markdown(title, description, extended), title=title):
        if chunk.anchor not in section_ids:
            scur = conn.execute(
                "INSERT INTO sections (doc_id, anchor, heading_path, ord, depth)"
                " VALUES (?, ?, ?, ?, ?)",
                (doc_id, chunk.anchor, chunk.heading_path, chunk.ord, chunk.depth),
            )
            section_ids[chunk.anchor] = int(scur.lastrowid)
        ccur = conn.execute(
            "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
            (section_ids[chunk.anchor], chunk.text, chunk.token_est),
        )
        if chunk.anchor == _DESCRIPTION_ANCHOR and description_chunk_id is None:
            description_chunk_id = int(ccur.lastrowid)
    return description_chunk_id


def ingest_cwe(
    conn: sqlite3.Connection, xml_path: str | Path, *, version: str, license: str
) -> int:
    """Load every Weakness and Category. Returns the entry count. Idempotent."""
    path = Path(xml_path)
    root = ET.parse(path).getroot()
    ns = root.tag.split("}")[0].strip("{")

    def q(tag: str) -> str:
        return f"{{{ns}}}{tag}"

    upsert_pack(
        conn,
        Pack(
            name=PACK_NAME,
            type="catalogue",
            version=version,
            source_url=SOURCE_URL,
            commit_sha=None,
            license=license,
            fetched_at=_now(),
        ),
    )
    pid = pack_id(conn, PACK_NAME)
    _clear_pack(conn, pid)

    source = path.name
    edges: list[tuple[str, str, str, str, str, str]] = []
    count = 0

    # Only these two containers are walked, so Views are skipped structurally
    # rather than by relying on any particular file not containing them.
    for weakness in root.findall(f"{q('Weaknesses')}/{q('Weakness')}"):
        entry_id = _entry_id(weakness.get("ID"))
        if entry_id is None:
            continue
        description = _flatten(weakness.find(q("Description")))
        extended = _flatten(weakness.find(q("Extended_Description")))
        chunk_id = _insert_entry_document(
            conn,
            pid,
            entry_id=entry_id,
            name=weakness.get("Name", ""),
            description=description,
            extended=extended,
        )
        conn.execute(
            "INSERT INTO catalogue_entries (pack_id, entry_id, kind, name, abstraction,"
            " status, description, extended_description, chunk_id)"
            " VALUES (?, ?, 'weakness', ?, ?, ?, ?, ?, ?)",
            (
                pid,
                entry_id,
                weakness.get("Name", ""),
                weakness.get("Abstraction"),
                weakness.get("Status", ""),
                description,
                extended,
                chunk_id,
            ),
        )
        count += 1

        for related in weakness.findall(f"{q('Related_Weaknesses')}/{q('Related_Weakness')}"):
            target = _entry_id(related.get("CWE_ID"))
            if target is None:
                continue
            rel = "cwe_child" if related.get("Nature") == "ChildOf" else "cwe_peer"
            edges.append(("cwe", entry_id, "cwe", target, rel, source))

    for category in root.findall(f"{q('Categories')}/{q('Category')}"):
        entry_id = _entry_id(category.get("ID"))
        if entry_id is None:
            continue
        # A Category's prose lives in Summary; only a Weakness has a Description.
        description = _flatten(category.find(q("Summary")))
        chunk_id = _insert_entry_document(
            conn,
            pid,
            entry_id=entry_id,
            name=category.get("Name", ""),
            description=description,
            extended="",
        )
        conn.execute(
            "INSERT INTO catalogue_entries (pack_id, entry_id, kind, name, abstraction,"
            " status, description, extended_description, chunk_id)"
            " VALUES (?, ?, 'category', ?, NULL, ?, ?, '', ?)",
            (
                pid,
                entry_id,
                category.get("Name", ""),
                category.get("Status", ""),
                description,
                chunk_id,
            ),
        )
        count += 1

        for member in category.findall(f"{q('Relationships')}/{q('Has_Member')}"):
            target = _entry_id(member.get("CWE_ID"))
            if target is None:
                continue
            edges.append(("cwe", entry_id, "cwe", target, "cwe_member", source))

    # OR IGNORE, not plain INSERT: the catalogue really does repeat edges, e.g.
    # CWE-120 declares ChildOf CWE-787 three times.
    #
    # Edges pointing outside the ingested set are kept. CWE's graph is a fact about
    # the catalogue, and a citation is often resolved by walking from a coarse
    # Category to a member that a caller has not yet fetched.
    conn.executemany(
        "INSERT OR IGNORE INTO links (from_kind, from_id, to_kind, to_id, rel, source)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        edges,
    )

    conn.commit()
    return count
