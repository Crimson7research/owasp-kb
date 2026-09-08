"""Types shared between core and server. No behaviour beyond citation formatting."""

from __future__ import annotations

from dataclasses import dataclass

PACK_LABELS = {"asvs": "ASVS", "masvs": "MASVS"}


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

    def __post_init__(self) -> None:
        """Reject a hit that cannot be cited.

        Citations are the product: the server's value is references a reviewer can
        check. A hit carrying neither a requirement id nor a doc_key would render
        as the literal string "None" (or "None#password-storage"), which looks
        like a citation and points nowhere. That is a bug in whichever retriever
        built the row, so fail at construction where it can be traced.
        """
        if not self.req_id and not self.doc_key:
            raise ValueError(
                "SearchHit needs a req_id or a doc_key to be citable; got neither "
                f"(pack={self.pack!r}, heading_path={self.heading_path!r}). A "
                "retriever built this from an incomplete row."
            )

    @property
    def citation(self) -> str:
        """A stable, human-checkable reference for this hit."""
        if self.req_id:
            label = PACK_LABELS.get(self.pack, self.pack)
            return f"{label} {self.pack_version} {self.req_id}"
        if self.anchor:
            return f"{self.doc_key}#{self.anchor}"
        return self.doc_key


@dataclass(frozen=True)
class RequirementRow:
    req_id: str
    chapter_id: str
    chapter_name: str
    section_id: str
    section_name: str
    text: str
    # None for a pack that does not define levels. MASVS 2.x dropped v1's L1/L2/R
    # and the surviving MAS profiles live on MASTG tests, not on MASVS controls.
    level: str | None


@dataclass(frozen=True)
class OutlineNode:
    anchor: str
    heading: str
    depth: int
    ord: int


@dataclass(frozen=True)
class RelatedEdge:
    """One edge out of ``from_id``. Every field except ``rel`` describes the target.

    ``abstraction`` is the *target's* abstraction level, never the source's: a
    caller comparing two ancestor chains is asking how coarse the shared node is,
    and the source is the id it already holds. It defaults to None so the ASVS
    relationships, whose targets are requirements and documents rather than
    catalogue entries, construct unchanged -- and it stays None for a catalogue
    target that is not itself ingested, which happens for real: CWE-320's four
    members are all outside the fixture catalogue.
    """

    rel: str
    to_kind: str
    to_id: str
    source: str
    abstraction: str | None = None


@dataclass(frozen=True)
class CatalogueEntry:
    """One entry of a catalogue pack -- a CWE Weakness or Category.

    ``abstraction`` is None for a Category, which carries no Abstraction attribute,
    and that None is stated rather than omitted: an agent comparing how coarse two
    cited ids are must be able to see that one of them has no level to compare.

    ``kind`` is load-bearing for the same reason. A Category's graph is Has_Member
    rather than ChildOf, so an ancestor comparison that treats the two alike is
    nonsense.
    """

    entry_id: str
    kind: str
    name: str
    abstraction: str | None
    status: str
    description: str
    extended_description: str
