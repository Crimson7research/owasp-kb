"""Types shared between core and server. No behaviour beyond citation formatting."""

from __future__ import annotations

from dataclasses import dataclass

PACK_LABELS = {"asvs": "ASVS"}


@dataclass(frozen=True)
class Chunk:
    anchor: str
    heading_path: str
    depth: int
    ord: int
    text: str
    token_est: int


@dataclass(frozen=True)
class SearchHit:
    pack: str
    pack_version: str
    req_id: str | None
    doc_key: str | None
    anchor: str | None
    heading_path: str
    text: str
    score: float

    @property
    def citation(self) -> str:
        """A stable, human-checkable reference for this hit."""
        if self.req_id:
            label = PACK_LABELS.get(self.pack, self.pack)
            return f"{label} {self.pack_version} {self.req_id}"
        if self.anchor:
            return f"{self.doc_key}#{self.anchor}"
        return str(self.doc_key)


@dataclass(frozen=True)
class RequirementRow:
    req_id: str
    chapter_id: str
    chapter_name: str
    section_id: str
    section_name: str
    text: str
    level: str


@dataclass(frozen=True)
class OutlineNode:
    anchor: str
    heading: str
    depth: int
    ord: int


@dataclass(frozen=True)
class RelatedEdge:
    rel: str
    to_kind: str
    to_id: str
    source: str
