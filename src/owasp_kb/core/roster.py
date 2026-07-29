"""Deterministic assembly of an assessment roster.

These rules live in code rather than in skill prose because the whole design
rests on the premise that instructions are not enforceable. An agent supplies
verdicts; this module decides whether the roster is complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType

VERDICTS = (
    "MET",
    "GAP",
    "N/A (verified)",
    "N/A (unverified)",
    "INSUFFICIENT EVIDENCE",
    "GAP (unconfirmed)",
)

# A GAP or GAP (unconfirmed) asserts a specific defect; without a file and line it
# would reach the report pointing at nothing. N/A and INSUFFICIENT EVIDENCE have no
# location by design -- a requirement that does not apply, or was never checked,
# points at nothing on purpose.
GAP_VERDICTS = frozenset({"GAP", "GAP (unconfirmed)"})


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
    remediation_quote: str | None = None
    trace: str | None = None
    covers: tuple[Coverage, ...] = field(default_factory=tuple)

    @property
    def file_line(self) -> str | None:
        if self.file is None or self.line is None:
            return None
        return f"{self.file}:{self.line}"

    @property
    def location_key(self) -> tuple | None:
        """Identity for deduplication, or None when the finding has no location.

        The verdict is part of the identity. Two requirements can legitimately
        resolve differently at one line -- one met, one gapped, both anchored to
        the same design document -- and that is valid input rather than a
        reporting mistake. Merging them kept whichever verdict arrived first and
        discarded the other, so a real GAP was counted as MET, the failure count
        came out short, and the answer depended on the order agents happened to
        report in. Only findings that agree may merge.
        """
        if self.file is None or self.line is None:
            return None
        return (self.file, self.line, self.cwe, self.verdict)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings sharing a (file, line, cwe, verdict), keeping every requirement.

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

# A verdict that asserts someone checked it must carry that check. GAP without a
# verifier shipped 172 unverified findings (#15); N/A without a refuter is the
# bulk-justified exemption that reached 67% in the single-agent baseline (#5).
CLAIMS_NEEDING_AN_ADVERSARY = MappingProxyType(
    {
        "GAP": "owasp-finding-verifier",
        "N/A (verified)": "owasp-exemption-refuter",
    }
)

# A verdict that concludes nothing cannot import a conclusion from a prior report,
# and the role prompts tell an agent to say when a verdict would depend on excluded
# material. Scanning those for the path it was just shown rejects honesty.
NON_ASSERTING_VERDICTS = frozenset({"INSUFFICIENT EVIDENCE", "N/A (unverified)"})


def build_roster(
    *,
    requirements: list[dict],
    findings: list[Finding],
    chapter_states: dict[str, str],
    excluded: list[str] | None = None,
    require_verification: bool = True,
    detail: bool = False,
) -> dict:
    """Assemble every requirement into exactly one verdict.

    The single-agent report could only assert completeness. Here it is decided:
    a requirement with no verdict becomes INSUFFICIENT EVIDENCE rather than
    disappearing, and a finding citing a requirement outside scope is an error
    rather than something quietly reconciled.

    ``require_verification`` rejects a claim that asserts a checked outcome but
    carries no trace from whoever checked it: a GAP without a verifier, or an
    'N/A (verified)' without a refuter. The first real run shipped 172 unverified
    findings with the verifier dispatched zero times -- its allowlist omitted the
    MCP tools it was told to load, and the fan-out it belonged to had already
    collapsed for the same reason (#19). Either way nothing required its result,
    which is why nothing noticed. Downgrading to
    'GAP (unconfirmed)' or 'N/A (unverified)' is the honest way past this;
    require_verification=False is the deliberate one.

    ``excluded`` lists prior assessment reports found in the target. A finding
    citing one in its file, evidence, trace or remediation is rejected: another
    assessment's conclusion is not evidence. This catches contamination that
    reached the report. It does not catch anchoring -- an agent that read a prior
    report and then went looking for confirming code produces a finding citing
    only source. Only the role prompts address that.

    ``NON_ASSERTING_VERDICTS`` -- 'INSUFFICIENT EVIDENCE' and 'N/A (unverified)' --
    are exempt from this scan. Both conclude nothing, so neither can import a false
    conclusion from a prior report, and the role prompts tell an agent to name that
    a verdict would depend on excluded material without naming the file itself --
    scanning those for the path it was just shown would reject the honest answer.
    A GAP or a verified N/A still asserts something a prior report could have
    supplied, so those stay in scope for the check.

    The response reports counts, per-chapter totals and the entries needing
    attention (``UNCERTAIN_VERDICTS``) rather than every entry, and each
    finding's identity and resolution rather than the evidence, trace and
    remediation the caller already supplied -- echoing those back was 72% of a
    109,038-character response. Pass ``detail=True`` for the full
    per-requirement entry list.
    """
    if excluded is not None:
        if isinstance(excluded, str):
            raise RosterError(
                "excluded must be a list of paths, not a single string: a string is "
                f"matched character by character and rejects everything. Pass ['{excluded}']."
            )
        non_strings = [p for p in excluded if not isinstance(p, str)]
        if non_strings:
            raise RosterError(
                f"excluded contains non-path entries {non_strings!r}; every entry must "
                "be a path string"
            )
        # A blank entry matches every finding, which is never what anyone means.
        excluded = [p.strip() for p in excluded if p.strip()]

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
        if finding.verdict in GAP_VERDICTS and finding.location_key is None:
            req_ids = ", ".join(cover.req_id for cover in finding.covers)
            raise RosterError(
                f"{finding.verdict} for {req_ids} has no file/line; a gap with no "
                "location would reach the report pointing at nothing"
            )
        for cover in finding.covers:
            if cover.req_id not in known:
                raise RosterError(
                    f"finding cites {cover.req_id}, which is not in the assessed set; "
                    "scope and findings disagree"
                )
            verdict_of[cover.req_id] = (finding.verdict, index)

    if excluded:
        contaminated: list[tuple[str, str]] = []
        for finding in merged:
            if finding.verdict in NON_ASSERTING_VERDICTS:
                continue
            cited = " ".join(
                part
                for part in (
                    finding.file,
                    finding.evidence,
                    finding.trace,
                    finding.remediation,
                )
                if part
            )
            for path in excluded:
                if path in cited:
                    contaminated.extend((cover.req_id, path) for cover in finding.covers)
        if contaminated:
            first_path: dict[str, str] = {}
            for req_id, path in contaminated:
                first_path.setdefault(req_id, path)
            pairs = list(first_path.items())
            shown = "; ".join(f"{req_id} cites {path}" for req_id, path in pairs[:3])
            more = f" and {len(pairs) - 3} more" if len(pairs) > 3 else ""
            raise RosterError(
                f"{len(pairs)} requirement(s) cite an excluded prior assessment "
                f"({shown}{more}). A prior report is someone else's conclusion, not "
                "evidence. Re-derive the finding from source, or drop it."
            )

    if require_verification:
        unverified: list[tuple[str, str]] = []
        for finding in merged:
            adversary = CLAIMS_NEEDING_AN_ADVERSARY.get(finding.verdict)
            if adversary is None or finding.trace:
                continue
            unverified.extend((cover.req_id, adversary) for cover in finding.covers)
        if unverified:
            by_role: dict[str, list[str]] = {}
            for req_id, adversary in unverified:
                by_role.setdefault(adversary, []).append(req_id)
            clauses = []
            for adversary, req_ids in sorted(by_role.items()):
                shown = ", ".join(req_ids[:5])
                more = f" and {len(req_ids) - 5} more" if len(req_ids) > 5 else ""
                clauses.append(f"{adversary} for {shown}{more}")
            raise RosterError(
                f"{len(unverified)} requirement(s) assert a checked outcome with no "
                f"trace. Dispatch {'; '.join(clauses)}, or record them as "
                "'GAP (unconfirmed)' or 'N/A (unverified)' to mark them unverified."
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
