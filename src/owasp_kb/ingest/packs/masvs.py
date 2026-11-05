"""Ingest MASVS from the release YAML into requirements plus one chunk each.

MASVS is a two-tier standard: 8 groups holding 24 controls, with no levels. The
group fills both the chapter and the section columns rather than a middle tier
being invented for it, and ``level`` is NULL -- v1's L1/L2/R are gone, and the
surviving MAS profiles live on MASTG tests, not on MASVS controls.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path

import yaml

from owasp_kb.core.chunking import estimate_tokens, slugify, split_prose
from owasp_kb.core.registry import Pack, pack_id, upsert_pack
from owasp_kb.ingest.packs.checklist_rows import clear_checklist_pack

PACK_NAME = "masvs"
SOURCE_URL = "https://github.com/OWASP/masvs"


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def ingest_masvs(
    conn: sqlite3.Connection, yaml_path: str | Path, *, version: str, license: str
) -> int:
    """Load every control. Returns the count ingested. Idempotent.

    ``version`` comes from the caller, never from the document. The release asset
    does stamp a real version, but it is ``v``-prefixed and so not string-equal to
    the value the lock and every citation use, and reading it would let a re-fetch
    move a citation's version.
    """
    data = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8")) or {}
    groups = data.get("groups") or []
    controls_total = sum(len(group.get("controls") or []) for group in groups)
    if not controls_total:
        # The same guard ingest_cwe carries: a source that parses and yields
        # nothing would leave a committed pack row over an empty pack, which reads
        # as a pack that exists and happens to be empty rather than as a failure.
        raise ValueError(
            f"{yaml_path} declares no controls; expected the MASVS release asset "
            "OWASP_MASVS.yaml, whose groups each carry a 'controls' list"
        )

    upsert_pack(
        conn,
        Pack(
            name=PACK_NAME,
            type="checklist",
            version=version,
            source_url=SOURCE_URL,
            commit_sha=None,
            license=license,
            fetched_at=_now(),
        ),
    )
    pid = pack_id(conn, PACK_NAME)
    clear_checklist_pack(conn, pid)

    ordinal = 0
    for group in groups:
        group_id, title = group["id"], group["title"]
        doc_id = int(
            conn.execute(
                "INSERT INTO docs (pack_id, doc_key, title, source_url) VALUES (?, ?, ?, ?)",
                (pid, group_id, f"{group_id}: {title}", SOURCE_URL),
            ).lastrowid
        )
        section_id = int(
            conn.execute(
                "INSERT INTO sections (doc_id, anchor, heading_path, ord, depth)"
                " VALUES (?, ?, ?, ?, ?)",
                (doc_id, slugify(group_id), title, 0, 2),
            ).lastrowid
        )

        # The group's own prose, as one or more chunks with no requirement row.
        # It answers "what does this category cover", which no control
        # statement does, and the retrieval query left-joins requirements so
        # every part is retrievable as MASVS-STORAGE#masvs-storage. Some
        # groups' prose (MASVS-PRIVACY, at v2.1.0) sits close enough to the
        # embedder's window that it can cross it once measured with a real
        # tokenizer rather than the char/4 proxy, so it is split on paragraph
        # boundaries like any oversized markdown section -- split_prose is the
        # same primitive chunk_markdown uses, applied here because this prose
        # has no heading structure for chunk_markdown to walk.
        overview = (group.get("description") or "").strip()
        if overview:
            text = f"{title}\n{overview}"
            for part in split_prose(text):
                conn.execute(
                    "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
                    (section_id, part, estimate_tokens(part)),
                )

        for control in group.get("controls") or []:
            statement = control["statement"].strip()
            description = (control.get("description") or "").strip()
            requirement_text = f"{statement}\n\n{description}".strip()
            chunk_text = f"{title}\n{control['id']}: {statement}\n{description}".strip()
            chunk_id = int(
                conn.execute(
                    "INSERT INTO chunks (section_id, text, token_est) VALUES (?, ?, ?)",
                    (section_id, chunk_text, estimate_tokens(chunk_text)),
                ).lastrowid
            )
            conn.execute(
                "INSERT INTO requirements (pack_id, req_id, chapter_id, chapter_name,"
                " section_id, section_name, text, level, ord, chunk_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                (
                    pid,
                    control["id"],
                    group_id,
                    title,
                    group_id,
                    title,
                    requirement_text,
                    ordinal,
                    chunk_id,
                ),
            )
            ordinal += 1

    conn.commit()
    return controls_total
