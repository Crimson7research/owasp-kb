"""Deterministic assembly of an assessment roster.

These rules live in code rather than in skill prose because the whole design
rests on the premise that instructions are not enforceable. An agent supplies
verdicts; this module decides whether the roster is complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

VERDICTS = (
    "MET",
    "GAP",
    "N/A (verified)",
    "N/A (unverified)",
    "INSUFFICIENT EVIDENCE",
    "GAP (unconfirmed)",
)


@dataclass(frozen=True)
class Coverage:
    """One requirement a finding covers, with enough context to cite it."""

    req_id: str
    chapter: str
    section: str


@dataclass(frozen=True)
class Finding:
    req_id: str
    chapter: str
    section: str
    verdict: str
    evidence: str
    file: str | None = None
    line: int | None = None
    cwe: str | None = None
    remediation: str | None = None
    trace: str | None = None
    covers: tuple[Coverage, ...] = field(default_factory=tuple)

    @property
    def file_line(self) -> str | None:
        if self.file is None or self.line is None:
            return None
        return f"{self.file}:{self.line}"

    @property
    def location_key(self) -> tuple | None:
        """Identity for deduplication, or None when the finding has no location."""
        if self.file is None or self.line is None:
            return None
        return (self.file, self.line, self.cwe)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings sharing a (file, line, cwe), keeping every requirement.

    The surviving finding carries each requirement id with its chapter and
    section, because a reader must see that one entry covers both -- dropping
    the second would silently cost a chapter its coverage in the roster.

    Findings with no location never merge: an INSUFFICIENT EVIDENCE verdict has
    no file or line, and collapsing those would fuse unrelated unknowns.
    """
    merged: dict[tuple, Finding] = {}
    order: list[tuple | int] = []
    unlocated: list[Finding] = []

    for finding in findings:
        own = Coverage(finding.req_id, finding.chapter, finding.section)
        key = finding.location_key
        if key is None:
            unlocated.append(replace(finding, covers=(own,)))
            order.append(len(unlocated) - 1)
            continue
        if key in merged:
            existing = merged[key]
            merged[key] = replace(existing, covers=(*existing.covers, own))
        else:
            merged[key] = replace(finding, covers=(own,))
            order.append(key)

    result: list[Finding] = []
    for item in order:
        result.append(unlocated[item] if isinstance(item, int) else merged[item])
    return result


MAX_VERIFICATION_ROUNDS = 2


def resolve_exemption(verdicts: list[str]) -> str:
    """Decide a chapter exemption from its refuters' verdicts.

    One refutation outweighs any number of confirmations: finding the exempted
    construct is positive evidence, while failing to find it is not. An
    exemption that survives only because nobody disproved it is reported as
    unverified, never as justified.
    """
    if "exemption_refuted" in verdicts:
        return "REFUTED"
    if "exemption_holds" in verdicts:
        return "N/A (verified)"
    if len(verdicts) < MAX_VERIFICATION_ROUNDS:
        return "ESCALATE"
    return "N/A (unverified)"


def resolve_finding(verdicts: list[str]) -> str:
    """Decide a finding from its verifiers' verdicts.

    A refutation outweighs a confirmation: a false positive in a client
    deliverable is far more costly than a false negative, which a later pass
    can recover.
    """
    if "refuted" in verdicts:
        return "DROPPED"
    if "confirmed" in verdicts:
        return "GAP"
    if len(verdicts) < MAX_VERIFICATION_ROUNDS:
        return "ESCALATE"
    return "GAP (unconfirmed)"


class RosterError(ValueError):
    """The supplied verdicts cannot form a complete, consistent roster."""


UNCERTAIN_VERDICTS = frozenset({"INSUFFICIENT EVIDENCE", "N/A (unverified)", "GAP (unconfirmed)"})


def build_roster(
    *,
    requirements: list[dict],
    findings: list[Finding],
    chapter_states: dict[str, str],
    require_verification: bool = True,
    detail: bool = False,
) -> dict:
    """Assemble every requirement into exactly one verdict.

    The single-agent report could only assert completeness. Here it is decided:
    a requirement with no verdict becomes INSUFFICIENT EVIDENCE rather than
    disappearing, and a finding citing a requirement outside scope is an error
    rather than something quietly reconciled.

    ``require_verification`` rejects a GAP carrying no verifier trace. The first
    real run shipped 172 unverified findings because the skill asked for a
    verifier and nothing required its result -- an instruction with no consumer
    gets skipped. Downgrading to 'GAP (unconfirmed)' is the honest way past this;
    require_verification=False is the deliberate one.

    The response reports counts, per-chapter totals and the entries needing
    attention (``UNCERTAIN_VERDICTS``) rather than every entry, and each
    finding's identity and resolution rather than the evidence, trace and
    remediation the caller already supplied -- echoing those back was 72% of a
    109,038-character response. Pass ``detail=True`` for the full
    per-requirement entry list.
    """
    known = {r["req_id"]: r for r in requirements}

    missing_chapters = {r["chapter"] for r in requirements} - set(chapter_states)
    if missing_chapters:
        raise RosterError(
            f"no applicability state for chapter(s) {', '.join(sorted(missing_chapters))}; "
            "every chapter must be APPLIES or an N/A state"
        )

    merged = dedupe_findings(findings)
    verdict_of: dict[str, tuple[str, int]] = {}
    for index, finding in enumerate(merged):
        if finding.verdict not in VERDICTS:
            raise RosterError(
                f"unknown verdict {finding.verdict!r}; expected one of {', '.join(VERDICTS)}"
            )
        for cover in finding.covers:
            if cover.req_id not in known:
                raise RosterError(
                    f"finding cites {cover.req_id}, which is not in the assessed set; "
                    "scope and findings disagree"
                )
            verdict_of[cover.req_id] = (finding.verdict, index)

    if require_verification:
        unverified = [
            cover.req_id
            for finding in merged
            if finding.verdict == "GAP" and not finding.trace
            for cover in finding.covers
        ]
        if unverified:
            shown = ", ".join(unverified[:5])
            more = f" and {len(unverified) - 5} more" if len(unverified) > 5 else ""
            raise RosterError(
                f"{len(unverified)} GAP finding(s) have no verifier trace ({shown}{more}). "
                "Dispatch owasp-finding-verifier for each, or mark them "
                "'GAP (unconfirmed)' to record them as unverified."
            )

    entries = []
    for req in requirements:
        req_id = req["req_id"]
        if req_id in verdict_of:
            verdict, finding_id = verdict_of[req_id]
        elif chapter_states[req["chapter"]] != "APPLIES":
            verdict, finding_id = chapter_states[req["chapter"]], None
        else:
            verdict, finding_id = "INSUFFICIENT EVIDENCE", None
        entries.append(
            {
                "req_id": req_id,
                "chapter": req["chapter"],
                "section": req["section"],
                "level": req.get("level"),
                "verdict": verdict,
                "finding_id": finding_id,
            }
        )

    counts: dict[str, int] = {}
    by_chapter: dict[str, dict[str, int]] = {}
    needs_attention = []
    for entry in entries:
        counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        chapter_counts = by_chapter.setdefault(entry["chapter"], {})
        chapter_counts[entry["verdict"]] = chapter_counts.get(entry["verdict"], 0) + 1
        if entry["verdict"] in UNCERTAIN_VERDICTS:
            needs_attention.append(entry)

    result = {
        "count": len(requirements),
        "counts": counts,
        "by_chapter": by_chapter,
        "needs_attention": needs_attention,
        "findings": [
            {
                "id": index,
                "verdict": f.verdict,
                "location": f.file_line,
                "cwe": f.cwe,
                "covers": [c.req_id for c in f.covers],
            }
            for index, f in enumerate(merged)
        ],
        "complete": sum(counts.values()) == len(requirements),
        # A waived roster must say so. 'GAP (unconfirmed)' announces itself by
        # landing in needs_attention; require_verification=False would otherwise
        # be invisible, making an unverified roster look identical to a verified
        # one -- which is the #15 defect again, behind a flag.
        "verification_required": require_verification,
    }
    if detail:
        result["entries"] = entries
    return result
